const jwt = require('jsonwebtoken');
const fs = require('fs');

export const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    const totken = authHeader && authHeader.split(' ')[1];
    
    if(!totken) {
        return res.sendStatus(401);
    }

    const publicKey = fs.readFileSync('./key/public.pem');
    const verify = jwt.verify(totken, publicKey, (error, user) => {
        if(error) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

export const generateToken = (payload, privateKey, expiresIn = '30s') => {
    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        expiresIn,
    });
}