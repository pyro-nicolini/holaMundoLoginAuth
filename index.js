const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt: expressJwt } = require('express-jwt');
const User = require('./user'); // Asegúrate de que user.js exporta el modelo User

// Conectar a MongoDB
mongoose.connect(' TU SERVER ')
    .then(() => console.log("Conectado a MongoDB"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

const app = express();

app.use(express.json());

// Middleware para manejar errores de autenticación
app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') {
        console.log('Error de autenticación:', err.message);
        return res.status(401).send('Token no válido');
    }
    next(err);
});

const secret = 'mi-string-secreto';

// Middleware para validar JWT
const validateJwt = expressJwt({ 
    secret: secret, 
    algorithms: ['HS256'],
    getToken: req => {
        const token = req.headers.authorization?.split(' ')[1];
        console.log('Token encontrado:', token); 
        return token; 
    }
}).unless({ path: ['/register', '/login'] });

// Función para firmar el token
const signToken = _id => jwt.sign({ _id }, secret);

// Crear o registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { body } = req;

    try {
        // Verificar si el usuario ya existe
        const isUser = await User.findOne({ email: body.email });
        if (isUser) {
            return res.status(403).send(`El usuario ${body.email} ya existe...`);
        }

        // Validar la contraseña
        if (!body.password || body.password.length < 6) {
            return res.status(400).send('La contraseña debe tener al menos 6 caracteres.');
        }

        // Hashear la contraseña
        const salt = await bcrypt.genSalt();
        const hashed = await bcrypt.hash(body.password, salt);
        
        // Crear un nuevo usuario
        const user = await User.create({ email: body.email, password: hashed, salt });
        const signed = signToken(user._id);
        res.status(201).send(signed);
    } catch (error) {
        console.error("Error al registrar el usuario:", error);
        return res.status(500).send("Error en el backend.");
    }
});

// Iniciar sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(403).send("Usuario y/o contraseña incorrecta...");
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(403).send("Usuario y/o contraseña incorrecta...");
        }

        const signed = signToken(user._id);
        res.status(200).send(signed);
    } catch (error) {
        console.error("Error al iniciar sesión:", error);
        return res.status(500).send("Error en el backend.");
    }
});

// Middleware para encontrar y asignar usuario
function findAndAssignUser(req, res, next) {
    console.log('req.auth:', req.auth); // Log para verificar el usuario
    if (!req.auth) {
        console.log('Usuario no autenticado:', req.auth);
        return res.status(401).send('Usuario no autenticado');
    }

    try {
        const userId = req.auth._id; // Asegúrate de que req.auth existe
        console.log('ID del usuario:', userId); // Debugging
        next(); // Continuar con la lógica
    } catch (error) {
        console.error('Error en findAndAssignUser:', error);
        return res.status(500).send('Error interno del servidor');
    }
}

// Ruta protegida
app.get('/lele', validateJwt, findAndAssignUser, (req, res) => {
    console.log('Usuario autenticado:', req.auth); // Deberías ver el usuario aquí
    res.send(req.auth); // Enviar la información del usuario
});

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});


