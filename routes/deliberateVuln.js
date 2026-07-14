/*
 * Copyright (c) 2014-2021 Bjoern Kimminich.
 * SPDX-License-Identifier: MIT
 */

const fs = require('fs')
const models = require('../models/index')
const insecurity = require('../lib/insecurity')
const request = require('request')
const logger = require('../lib/logger')
const ALLOWED_URLS = new Set((process.env.SSRF_ALLOWED_URLS || '').split(',').map(h => h.trim()).filter(Boolean))

module.exports = function deliberate () {
  return (req, res, next) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = insecurity.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!ALLOWED_URLS.has(url)) {
          return next(new Error('Blocked SSRF attempt to disallowed URL'))
        }
        let safeUrl
        for (const allowed of ALLOWED_URLS) {
          if (allowed === url) { safeUrl = allowed; break }
        }
        if (!safeUrl) {
          return next(new Error('Blocked SSRF attempt to disallowed URL'))
        }
        const imageRequest = request
          .get({ uri: safeUrl, followRedirect: false })
          .on('error', function (err) {
            models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: safeUrl }) }).catch(error => { next(error) })
            logger.warn('Error retrieving user profile image: ' + err.message + '; using image link directly')
          })
          .on('response', function (res) {
            if (res.statusCode === 200) {
              const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(safeUrl.split('.').slice(-1)[0].toLowerCase()) ? safeUrl.split('.').slice(-1)[0].toLowerCase() : 'jpg'
              models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch(error => { next(error) })
            } else models.User.findByPk(loggedInUser.data.id).then(user => { return user.update({ profileImage: safeUrl }) }).catch(error => { next(error) })
          })
      } else {
        next(new Error('Blocked illegal activity by ' + req.connection.remoteAddress))
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
