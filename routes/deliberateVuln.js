/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const fs = require('fs')
const models = require('../models/index')
const insecurity = require('../lib/insecurity')
const request = require('request')
const logger = require('../lib/logger')
const dns = require('dns')
const net = require('net')
const { URL } = require('url')

const ALLOWED_HOSTS = ['placekitten.com', 'via.placeholder.com', 'placehold.co', 'picsum.photos']

function isPrivateIPv4 (ip) {
  const parts = ip.split('.').map(Number)
  if (parts[0] === 10) return true
  if (parts[0] === 127) return true
  if (parts[0] === 0) return true
  if (parts[0] === 169 && parts[1] === 254) return true
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
  if (parts[0] === 192 && parts[1] === 168) return true
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true
  if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true
  return false
}

function isPrivateIPv6 (ip) {
  const lower = ip.toLowerCase()
  if (lower === '::1' || lower === '::') return true
  if (/^fe[89ab][0-9a-f]/.test(lower)) return true
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true
  if (lower.startsWith('ff')) return true
  return false
}

function isPrivateIP (ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip)
  if (net.isIPv6(ip)) return isPrivateIPv6(ip)
  return false
}

function validateUrl (inputUrl, cb) {
  let parsed
  try {
    parsed = new URL(inputUrl)
  } catch (e) {
    return cb(false)
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return cb(false)
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) return cb(false)
  dns.lookup(parsed.hostname, { all: true }, (err, addresses) => {
    if (err || !addresses) return cb(false)
    if (addresses.some(a => isPrivateIP(a.address))) return cb(false)
    return cb(true)
  })
}

module.exports = function deliberate () {
  return (req, res, next) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        validateUrl(url, (isValid) => {
          if (!isValid) {
            return next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
          }
          models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: url }) }).catch(error => { next(error) })
        })
      } else {
        next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
