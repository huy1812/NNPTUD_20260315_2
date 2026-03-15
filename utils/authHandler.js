let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

// Đọc private key và public key - dùng đường dẫn tuyệt đối
let privateKey, publicKey;

try {
    privateKey = fs.readFileSync(path.join(__dirname, '../private.key'), 'utf8');
    publicKey = fs.readFileSync(path.join(__dirname, '../public.key'), 'utf8');
    console.log('Keys loaded successfully');
} catch (err) {
    console.error('Error loading keys:', err.message);
    // Fallback to HS256 if keys not found
    privateKey = 'secret';
    publicKey = 'secret';
}

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            // Require inside function để tránh circular dependency
            let userController = require('../controllers/users')
            
            let token = req.headers.authorization;
            console.log('Token header:', token ? 'received' : 'missing');
            
            if (!token || !token.startsWith("Bearer")) {
                console.log('Invalid token format');
                res.status(403).send({ message: "ban chua dang nhap" })
                return;
            }
            
            token = token.split(' ')[1]
            console.log('Verifying token...');
            
            // Thử RS256 trước, rồi fallback HS256
            let result;
            try {
                result = jwt.verify(token, publicKey, { algorithm: 'RS256' });
            } catch (e) {
                console.log('RS256 failed, trying HS256...');
                result = jwt.verify(token, publicKey);
            }
            console.log('Token verified, userId:', result.id);
            
            if (result.exp * 1000 < Date.now()) {
                console.log('Token expired');
                res.status(403).send({ message: "ban chua dang nhap" })
                return;
            }
            
            let getUser = await userController.GetUserById(result.id);
            console.log('GetUserById result:', getUser);
            
            if (!getUser || (Array.isArray(getUser) && getUser.length === 0)) {
                console.log('User not found');
                res.status(403).send({ message: "ban chua dang nhap" })
            } else {
                console.log('User found, proceeding');
                req.user = getUser;
                next();
            }
        } catch (error) {
            console.error('CheckLogin error:', error.message);
            console.error('Stack:', error.stack);
            res.status(403).send({ message: "ban chua dang nhap" })
        }

    },
    SignToken: function (userId) {
        // Detect which algorithm to use
        let options = { expiresIn: '1d' };
        
        if (privateKey && (privateKey.includes('BEGIN RSA') || privateKey.includes('BEGIN PRIVATE KEY'))) {
            options.algorithm = 'RS256';
        }
        
        return jwt.sign({
            id: userId
        }, privateKey, options)
    }
}