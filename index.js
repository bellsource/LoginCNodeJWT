const express = require('express');
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
require('dotenv').config()

const app = express();

// capturar body
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());

// Conexión a Base de datos
const uri = `mongodb+srv://${process.env.USER}:${process.env.PASSWORD}@cluster0.xfs8p.mongodb.net/${process.env.DBNAME}?retryWrites=true&w=majority`;
const option =    { useNewUrlParser: true, useUnifiedTopology: true };
mongoose.connect(uri,option)
.then(() => console.log('Base de datos conectada'))
.catch(e => console.log('error db:', e))

// import routes
const authRoutes=require("./routes/auth");
const validaToken = require('./routes/validate-token');
const admin = require('./routes/admin');


// route middlewares
app.use('/api/user', authRoutes);
app.use('/api/admin', validaToken,admin);


app.get('/', (req, res) => {
    res.json({
        estado: true,
        mensaje: 'funciona!' 
    })
});

// iniciar server
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`servidor andando en: ${PORT}`)
})