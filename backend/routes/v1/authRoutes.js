import express from "express";
import { 
    createAdmin, createCustomer, logoutAdmin, logoutCustomer, loginAdmin, 
    loginCustomer,createArtisan, loginArtisan, logoutArtisan, refreshAdminToken,
    refreshCustomerToken, refreshArtisanToken,
    sendOtp, verifyOtp, verifyUsersEmail,

 } 
 from "../../controllers/authController/auth.js";

 import { authenticateAccessToken, verifyRefreshAccessToken } from "../../../middleware/auth.js";

const router = express.Router()







// admins
router.post('/admin/create', createAdmin)
router.post('/admin/login',  loginAdmin)

router.post('/admin/logout', authenticateAccessToken, logoutAdmin)
// refresh token
router.post('/admin/refresh', verifyRefreshAccessToken, refreshAdminToken)


// customers
router.post('/customer/create', createCustomer)
router.post('/customer/login', loginCustomer)

router.post('/customer/logout', authenticateAccessToken, logoutCustomer)
// refresh token
router.post('/customer/refresh', verifyRefreshAccessToken, refreshCustomerToken)

// artisans
router.post('/artisan/create', createArtisan)
router.post('/artisan/login', loginArtisan)

router.post('/artisan/logout', authenticateAccessToken, logoutArtisan)
// refresh token
router.post('/artisan/refresh', verifyRefreshAccessToken, refreshArtisanToken)

// otp 
router.post('/otp/send', sendOtp)

router.post('/otp/verify', verifyOtp)

router.get('/verifyemail/:email/:otp', verifyUsersEmail)


export { router as authRouter }


