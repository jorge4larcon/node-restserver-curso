const express = require('express');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const Usuario = require('../models/usuario');

const app = express();

app.post('/login', (req, res) => {

    let body = req.body;

    Usuario.findOne({email: body.email}, (err, dbUser) => {
        if (err) {
            return res.status(500).json({
                ok: false,
                err
            });
        }

        if (!dbUser) {
            return res.status(400).json({
                ok: false,
                err: {
                    msg: "(Usuario) o contrasenia incorrectos"
                }
            });
        }

        if (!bcrypt.compareSync(body.password, dbUser.password)) {
            return res.status(400).json({
                ok: false,
                err: {
                    msg: "Usuario o (contrasenia) incorrectos"
                }
            });
        }

        let token = jwt.sign({
            usuario: dbUser,            
        }, process.env.SEED, { expiresIn: process.env.CADUCIDAD_TOKEN });


        res.status(200).json({
            ok: true,
            usuario: dbUser,
            token
        });

    });
});


module.exports = app;

