const jwt = require('jsonwebtoken');

// middleware to validar token (rutas protegidas), valido lo q viene del front
const verifyToken = (req, res, next) => {
    const token = req.header('auth-token')//lee el token del req 
    if (!token) return res.status(401).json({ error: 'Acceso denegado' })
    try {
        const verificar = jwt.verify(token, process.env.TOKEN_SECRET)
        req.user = verificar
        next() // continuamos
    } catch (error) {
        res.status(400).json({error: 'token no es válido'})
    }
}

module.exports = verifyToken;