// passport config for security 
require('dotenv').config();

const { Strategy, ExtractJwt } = require('passport-jwt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

// JWT Secret should be loaded from env
const JWT_SECRET = process.env.JWT_SECRET || '123456';

/**
 * passport jwt configuration
 * using BEARER token auth scheme
 * please read https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly/25843058
 * for more information on BEARER Token
 * 
 */
const PASSPORT_JWT_OPTS = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: JWT_SECRET
};

/**
 * Jwt strategy passport middleware for jwt tokens
 * @param {*} passport - passport instance
 * @param {*} Users
 */
const passportJWTStrategy = ({ passport, Users }) => {
    passport.use(
        new Strategy(PASSPORT_JWT_OPTS, async (payload, done) => {
            // jwt authentication by finding user id
            try {
                const authenticatedUser = await Users.findByPk(payload.id);
                if (authenticatedUser) {
                    return done(null, {
                        id: authenticatedUser.id,
                        name: authenticatedUser.name,
                        email: authenticatedUser.email,
                    });
                }
                // no valid user found
                return done(null, false, 'Invalid token or token expired');
            }
            catch (err) {
                console.error(err);
                return done(null, false);
            }
        })
    );
};

/**
 * Login route for authentication and setting jwt
 * @param {*} app - express app instance
 * @param {*} Users - users sequelize model instance
 */
const passportLoginRoute = ({ app, Users }) => {
    app.post('/api/login', async (req, res) => {
        const email = req.body.email;
        const password = req.body.password;
        const attemptedUser = await Users.findOne({ where: { email } });
        // TODO: standard error message - probably good to come up with a standard error message lib here  -ds
        const errorMsg = 'No Account Found';
        // user found login them in and return jwt token;
        if (attemptedUser) {
            // using bcrypt to compare passwords
            if (bcrypt.compareSync(password, attemptedUser.password)) {
                const payload = {
                    id: attemptedUser.id,
                    email: attemptedUser.email,
                    isAdmin: attemptedUser.admini
                };
                // sign the token
                try {
                    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: 36000 });
                    return res.json({
                        success: true,
                        token
                    });
                } catch (err) {
                    return res.status(500)
                        .json({
                            error: "Error signing token",
                            raw: err
                        });
                }
            } else {
                // passwords don't match - show generic error for security reasons
                return res.status(401).json({ errorMsg });
            }
        } else {
            // user not found
            return res.status(401).json({ errorMsg });
        }
    });
};

module.exports = {
    passportJWTStrategy,
    passportLoginRoute
} 
