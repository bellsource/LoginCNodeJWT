const router = require('express').Router();

router.get('/', (req, res) => {
    res.json({
        error: null,
        data: {
            title: 'mi ruta protegida',
            user: req.user//creado en validate-token
        }
    })
})

module.exports = router