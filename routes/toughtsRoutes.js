const express = require('express')
const router = express.Router()
const ToughtController = require('../controllers/ToughtController')

const checkAuth = require('../helpers/auth').checkAuth

router.get('/add', checkAuth, ToughtController.createTought) 
router.post('/add', checkAuth, ToughtController.createToughtPost) 
router.get('/edit/:id', checkAuth, ToughtController.editTought) 
router.post('/edit', checkAuth, ToughtController.editToughtSave) 
router.get('/dashboard', checkAuth, ToughtController.dashboard) 
router.post('/remove', checkAuth, ToughtController.toughtRemove) 
router.get('/', ToughtController.showToughts)

module.exports = router
