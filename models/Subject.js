const mongoose = require('mongoose');

const ModuleSchema = new mongoose.Schema({
    moduleCode: {
        type: String,
        required: true
    },
    moduleName: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    }
});

const Subject = mongoose.model('Subject', ModuleSchema);

module.exports = Subject;