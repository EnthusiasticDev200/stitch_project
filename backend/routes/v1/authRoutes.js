import express from "express";
import { 
    createAdmin, createCustomer, logoutAdmin, logoutCustomer, loginAdmin, 
    loginCustomer,createArtisan, loginArtisan, logoutArtisan, refreshTokens
 } from "../../controllers/authController/auth.js";

 import { authenticateAccessToken, verifyRefreshAccessToken } from "../../../middleware/auth.js";

const router = express.Router()







// admins
router.post('/admin/create', createAdmin)
router.post('/admin/login',  loginAdmin)

router.post('/admin/logout', authenticateAccessToken, logoutAdmin)


// customers
router.post('/customer/create', createCustomer)
router.post('/customer/login', loginCustomer)

router.post('/customer/logout', authenticateAccessToken, logoutCustomer)

// artisans
router.post('/artisan/create', createArtisan)
router.post('/artisan/login', loginArtisan)

router.post('/artisan/logout', authenticateAccessToken, logoutArtisan)

// refresh token
router.post('/token/refresh', verifyRefreshAccessToken, refreshTokens)


export { router as authRouter }


