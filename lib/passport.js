'use strict';

const config = require('config');
const log = require('npmlog');
const _ = require('./translate')._;
const util = require('util');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const csrf = require('csurf');
const bodyParser = require('body-parser');

const users = require('../models/users');
const { nodeifyFunction, nodeifyPromise } = require('./nodeify');
const interoperableErrors = require('../shared/interoperable-errors');
const contextHelpers = require('./context-helpers');

let LdapStrategy;
try {
    LdapStrategy = require('passport-ldapjs').Strategy; // eslint-disable-line global-require
} catch (E) {
    if (config.ldap.enabled) {
        log.info('LDAP', 'Module "passport-ldapjs" not installed. It will not be used for LDAP auth.');
    }
}

let LdapAuthStrategy;
try {
    LdapAuthStrategy = require('passport-ldapauth').Strategy; // eslint-disable-line global-require
} catch (E) {
    if (config.ldapauth.enabled) {
        log.info('LDAP', 'Module "passport-ldapauth" not installed. It will not be used for LDAP auth.');
    }
}

module.exports.csrfProtection = csrf({
    cookie: true
});

module.exports.parseForm = bodyParser.urlencoded({
    extended: false,
    limit: config.www.postsize
});

module.exports.loggedIn = (req, res, next) => {
    if (!req.user) {
        next(new interoperableErrors.NotLoggedInError());
    } else {
        next();
    }
};

module.exports.authByAccessToken = (req, res, next) => {
    nodeifyPromise((async () => {
        if (!req.query.access_token) {
            res.status(403);
            return res.json({
                error: 'Missing access_token',
                data: []
            });
        }

        try {
            const user = await users.getByAccessToken(req.query.access_token);
            req.user = user;
            next();
        } catch (err) {
            if (err instanceof interoperableErrors.NotFoundError) {
                res.status(403);
                return res.json({
                    error: 'Invalid or expired access_token',
                    data: []
                });
            } else {
                res.status(500);
                return res.json({
                    error: err.message || err,
                    data: []
                });
            }
        }
    })(), next);
};

module.exports.setup = app => {
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports.restLogout = (req, res) => {
    req.logout();
    res.json();
};


module.exports.login = (req, res, next) => {
    let authMode = config.ldapauth.enabled ? 'ldapauth' : config.ldap.enabled ? 'ldap' : 'local';
    passport.authenticate(authMode, (err, user, info) => {
        if (err) {
            return next(err);
        }

        if (!user) {
            return next(new interoperableErrors.IncorrectPasswordError());
        }

        req.logIn(user, err => {
            if (err) {
                return next(err);
            }

            if (req.body.remember) {
                // Cookie expires after 30 days
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            } else {
                // Cookie expires at end of session
                req.session.cookie.expires = false;
            }

            return res.json();
        });
    })(req, res, next);
};

if (config.ldap.enabled && LdapStrategy) {

    log.info('Using LDAP auth (passport-ldapjs)');

    let opts = {
        server: {
            url: 'ldap://' + config.ldap.host + ':' + config.ldap.port
        },
        base: config.ldap.baseDN,
        search: {
            filter: config.ldap.filter,
            attributes: [config.ldap.uidTag, config.ldap.nameTag, 'mail'],
            scope: 'sub'
        },
        uidTag: config.ldap.uidTag,
        bindUser: config.ldap.bindUser,
        bindPassword: config.ldap.bindPassword
    };

    passport.use(new LdapStrategy(opts, nodeifyFunction(async (profile) => {
        try {
            const user = await users.getByUsername(profile[config.ldap.uidTag]);

            return {
                id: user.id,
                username: user.username,
                name: profile[config.ldap.nameTag],
                email: profile.mail,
                role: user.role
            };

        } catch (err) {
            if (err instanceof interoperableErrors.NotFoundError) {
                const userId = await users.create(null, {
                    username: profile[config.ldap.uidTag],
                    role: config.ldap.newUserRole,
                    namespace: config.ldap.newUserNamespaceId
                });

                return {
                    id: userId,
                    username: profile[config.ldap.uidTag],
                    name: profile[config.ldap.nameTag],
                    email: profile.mail,
                    role: config.ldap.newUserRole
                };
            } else {
                throw err;
            }
        });
    }));
} else if (config.ldapauth.enabled && LdapAuthStrategy) {
    log.info('Using LDAP auth (passport-ldapauth)');
    let opts = {
        server: {
            url: 'ldap://' + config.ldap.host + ':' + config.ldap.port,
            searchBase: config.ldapauth.baseDN,
            searchFilter: config.ldapauth.filter,
            searchAttributes: [config.ldapauth.uidTag, 'mail'],
            bindDN: config.ldapauth.bindUser,
            bindCredentials: config.ldapauth.bindPassword
        }
    };

    passport.use(new LdapAuthStrategy(opts, (profile, done) => {
        users.findByUsername(profile[config.ldapauth.uidTag], (err, user) => {
            if (err) {
                return done(err);
            }

            if (!user) {
                // password is empty for ldap
                users.add(profile[config.ldapauth.uidTag], '', profile.mail, (err, id) => {
                    if (err) {
                        return done(err);
                    }

                    return done(null, {
                        id,
                        username: profile[config.ldapauth.uidTag]
                    });
                });
            } else {
                return done(null, {
                    id: user.id,
                    username: user.username
                });
            }
        });
    }));
} else {
    log.info('Using local auth');
    module.exports.authMethod = 'local';
    module.exports.isAuthMethodLocal = true;

    passport.use(new LocalStrategy(nodeifyFunction(async (username, password) => {
        return await users.getByUsernameIfPasswordMatch(username, password);
    })));

    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser((id, done) => nodeifyPromise(users.getById(contextHelpers.getAdminContext(), id), done));
}

