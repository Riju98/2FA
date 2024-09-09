var passport = require('passport'),
    LocalStrategy = require('passport-local').Strategy,
    BasicStrategy = require('passport-http').BasicStrategy,
    ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy,
    BearerStrategy = require('passport-http-bearer').Strategy,
    OAuth2Client = require('./models/oauth2client'),
    OAuth2Token = require('./models/oauth2token'),
    User = require('./models/user'),
    speakeasy = require('speakeasy'),
    QRCode = require('qrcode');

// Local authentication strategy for passportjs, used for web logins
passport.use(new LocalStrategy({
        usernameField: 'username'
    },
    function (username, password, done) {
        User.authenticate(username, password, function (err, user, params) {
            if (err || !user) {
                return done(err, user, params);
            }

            // If 2FA is enabled, verify the token
            if (user.twoFactorEnabled) {
                if (!params || !params.otp) {
                    return done(null, false, { message: '2FA token required' });
                }

                const isVerified = user.verifyTwoFactorToken(params.otp);
                if (!isVerified) {
                    return done(null, false, { message: 'Invalid 2FA token' });
                }
            }

            return done(null, user, params);
        });
    }));

// Standard basic authentication strategy, used for REST-based logins
passport.use(new BasicStrategy(
    function (username, password, done) {
        User.authenticate(username, password, function (err, user, params) {
            if (err || !user) {
                return done(err, user, params);
            }

            // If 2FA is enabled, verify the token
            if (user.twoFactorEnabled) {
                if (!params || !params.otp) {
                    return done(null, false, { message: '2FA token required' });
                }

                const isVerified = user.verifyTwoFactorToken(params.otp);
                if (!isVerified) {
                    return done(null, false, { message: 'Invalid 2FA token' });
                }
            }

            return done(null, user, params);
        });
    }
));

// Authentication strategy used by OAuth clients, uses a custom name 'oAuthBasic'
passport.use('oAuthBasic', new BasicStrategy(
    function (username, password, done) {
        OAuth2Client.findOne({
            clientId: username
        }, function (error, client) {
            if (error) {
                return done(error);
            }
            if (!client) {
                return done(null, false);
            }
            if (client.clientSecret !== password) {
                return done(null, false);
            }
            return done(null, client);
        });
    }
));

// A client-password strategy for authorizing requests for tokens
passport.use(new ClientPasswordStrategy(
    function (clientId, clientSecret, done) {
        OAuth2Client.findOne({
            clientId: clientId
        }, function (error, client) {
            if (error) {
                return done(error);
            }
            if (!client) {
                return done(null, false);
            }
            if (client.clientSecret !== clientSecret) {
                return done(null, false);
            }
            return done(null, client);
        });
    }
));

// A bearer strategy to authorize API requests by OAuth2 tokens
passport.use(new BearerStrategy(
    function (accessToken, done) {
        OAuth2Token.findOne({
            token: accessToken
        }, function (error, oauth2token) {
            if (error) {
                return done(error);
            }
            if (!oauth2token) {
                return done(null, false);
            }
            User.findOne({
                _id: oauth2token.user
            }, function (error, openhabUser) {
                if (error) {
                    return done(error);
                }
                if (!openhabUser) {
                    return done(null, false);
                }
                var info = {
                    scope: oauth2token.scope
                };
                done(null, openhabUser, info);
            });
        });
    }
));

passport.serializeUser(function (user, done) {
    done(null, user._id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

// Route to enable 2FA
module.exports.enableTwoFactor = async function (req, res) {
    try {
        const user = await User.findById(req.user.id); // Ensure this retrieves the correct user

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const secret = User.generateTwoFactorSecret();

        user.twoFactorSecret = secret.base32;
        user.twoFactorEnabled = true;
        await user.save();

        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        res.json({ qrCodeUrl });
    } catch (error) {
        res.status(500).json({ message: 'Error enabling 2FA' });
    }
};

// Middleware to verify 2FA OTP
module.exports.verifyTwoFactor = function (req, res, next) {
    if (!req.user.twoFactorEnabled) {
        return next(); // 2FA not enabled, proceed to the next middleware
    }

    const otp = req.body.otp;
    if (!otp) {
        return res.status(401).json({ message: '2FA token required' });
    }

    const isVerified = req.user.verifyTwoFactorToken(otp);
    if (!isVerified) {
        return res.status(401).json({ message: 'Invalid 2FA token' });
    }

    next(); // 2FA verified, proceed to the next middleware
};

