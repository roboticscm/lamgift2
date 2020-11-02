require('dotenv').config();

import {authenticateToken, generateToken} from './auth';

const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const fs = require('fs');

app.use(express.json());

app.get('/list', authenticateToken, (req, res, next) => {
    res.json({'OK': true});
});

export let refreshTokens = [];

app.post('/token', (req, res, next) => {
    const refreshToken = req.body.refreshToken;

    if(!refreshToken) {
        return res.sendStatus(401);
    }

    if(!refreshTokens.includes(refreshToken)) {
        return res.sendStatus(403);
    }

    const publicKey = fs.readFileSync('./key/public.pem');

    jwt.verify(refreshToken, publicKey, (error, user) => {
        if(error) {
            return res.sendStatus(403);
        }
        const privateKey = fs.readFileSync('./key/private.pem');
        const payload = {username: user.username};
        const accessToken = generateToken(payload, privateKey);
        return res.json({accessToken});
    });
});

app.post('/login', (req, res, next) => {
    const username = req.body.username;

    const payload = {username};
    const privateKey = fs.readFileSync('./key/private.pem');

    const accessToken = generateToken(payload, privateKey);
    const refreshToken = generateToken(payload, privateKey, '365d');
    
    refreshTokens.push(refreshToken);

    res.json({accessToken, refreshToken});
});

const port = process.env.PORT || 3000;
app.listen(port, console.log(`Server is running on port: ${port}`));

