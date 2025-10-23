import express from "express";

import { authRouter } from "./v1/authRoutes.js";

const router = express.Router()



router.use('/auth', authRouter)






export default router