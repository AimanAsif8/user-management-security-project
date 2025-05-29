const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.session.token;

    if (!token) {
        return res.status(401).send('Access Denied: No Token Provided!');
    }

    try {
        const verified = jwt.verify(token, 'your-secret-key');
        req.user = verified;
        next();
    } catch (err) {
        return res.status(400).send('Invalid Token');
    }
};

module.exports = verifyToken;