const router = require('express').Router();
//llamo al archivo User.js
const User = require("../models/User");

const Joi = require("@hapi/joi");

const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');

//validacion con @hapi/joi registro
const schemaRegister = Joi.object({
    name: Joi.string().min(6).max(255).required(),
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()
})

router.post('/register', async (req, res) => {
    
    // validaciones de usuarios
    const { error } = schemaRegister.validate(req.body)
    
    if (error) {
        return res.status(400).json(
            {error: error.details[0].message}
        )
    }

    //validacion email
    const isEmailExist = await User.findOne({ email: req.body.email });
    if (isEmailExist) {
        return res.status(400).json(
            {error: 'Email ya registrado'}
        )
    }

    //hash de contraseña
    const salt = await bcrypt.genSalt(10);
    const password = await bcrypt.hash(req.body.password, salt);

    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: password
    });
    /**Aca tomaba la contraseña sin hashear del body, arriba tomo la del bcrypt.hash */
    //     const user = new User({
    //     name: req.body.name,
    //     email: req.body.email,
    //     password: req.body.password
    // });
    try {
        const savedUser = await user.save();
        res.json({
            error: null,
            data: savedUser
        })
    } catch (error) {
        res.status(400).json({error})
    }
})

//validacion con @hapi/joi login
const schemaLogin = Joi.object({
    email: Joi.string().min(6).max(255).required().email(),
    password: Joi.string().min(6).max(1024).required()
})

router.post('/login', async (req, res) => {
    // validaciones
    const { error } = schemaLogin.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message })
    //buscamos que el usuario existe, si es asi lo guardamos en user
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ error: 'Usuario no registrado' });
    //paso el usuario, ahora validamos la contraseña, y la comparo con el user que ya tengo sus datos
    const passValida = await bcrypt.compare(req.body.password, user.password);
    if (!passValida) return res.status(400).json({ error: 'contraseña no válida' })


    // creo token
    const token = jwt.sign({
        name: user.name,//payload
        id: user._id //payload
    }, process.env.TOKEN_SECRET)

    // res.json({
    //     error: null,
    //     mensaje: 'exito bienvenido',
    //     token: token,
    // })

    res.header('auth-token', token).json({//se manda el token en el header
        error: null,
        data: {token}
    })
})

module.exports = router;