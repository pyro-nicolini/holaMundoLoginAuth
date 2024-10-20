const mongoose = require('mongoose');

// Definir el esquema del usuario
const User = mongoose.model('User', {
    email: { type: String, required: true },
    password: { type: String, required: true },
    salt: { type: String, default: 'user' }
});

// Exportar el modelo
module.exports = User;
