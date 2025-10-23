import jwt from 'jsonwebtoken'

import dotenv from 'dotenv'

dotenv.config()



const authenticateAccessToken = ( req, res, next) =>{
    try{
        const adminToken = req.cookies.admin_token;
        const customerToken = req.cookies.customer_token
        const artisanToken = req.cookies.artisan_token
        if ( !adminToken && !customerToken && !artisanToken){
            return res.status(401).json({message:"Unauthorized! Invalid or expired token"})
        }
        let decoded;
        if ( adminToken ) {
            decoded = jwt.verify(adminToken, process.env.JWT_SECRET, {
                algorithms : ['HS256']})
            req.adminId = decoded.adminId;
            req.adminUsername = decoded.adminUsername;
            req.role = decoded.role
        }
        if ( customerToken ){
            decoded = jwt.verify(customerToken, process.env.JWT_SECRET, {
                algorithms : ['HS256']})
            req.customerId = decoded.customerId;
            req.customerUsername = decoded.customerUsername;
        }
        if ( artisanToken ){
            decoded = jwt.verify(artisanToken, process.env.JWT_SECRET, {
                algorithms : ['HS256']})
            req.artisanId = decoded.artisanId;
            req.artisanUsername = decoded.artisanUsername;
            req.artisanRole = decoded.artisanRole
        }
        next()
    }catch(err){
        console.log('Error authenicating access token', err.stack)
        return res.status(500).json({
            message : "Access code authentiation failed",
            error : err.message
        })
    }
}
const verifyRefreshAccessToken = (req, res, next)=>{
    try{
        const refreshToken = req.cookies.refresh_admin_token || req.cookies.refresh_customer_token || req.cookies.refresh_stylist_token
        if ( !refreshToken ) return res.status(401).json({
            message : "No refresh token found"
        })
        const decoded = jwt.verify(refreshToken, process.env.REFRESH_JWT_SECRET, {
            algorithms : [`HS256`] })

        req.adminId = decoded.adminId
        req.adminUsername = decoded.adminUsername

        req.customerId = decoded.customerId
        req.customerUsername = decoded.customerUsername

        req.artisanId = decoded.artisanId
        req.artisanUsername = decoded.artisanUsername;
        
        if ( !req.adminId && !req.customerId && !req.artisanId){
            return res.stauts(401).json({message: "Invalid or expired token"})
        }
        next()
    }catch(error){
         console.log("Error validating refresh token: ", error)
        return res.status(500).json({
            message:"Refresh token validation error",
            error: error.stack
        })
    }
}

const requireSuperuser = (req, res, next)=>{
    if( !req.adminUsername || req.role !== process.env.ROLE) return res.status(403).json({message:"Restricted route for superuser"})
    next();
}
const adminOnly = async (req, res, next)=>{
    if (!req.role || !req.adminUsername) return res.status(403).json({message:" Sorry! Strictly for admins"})
    next()
}

const customerOnly = async (req, res, next)=>{
    if (!req.customerId || !req.username) return res.status(403).json({message:" Sorry! Strictly for customers"})
    next()
}
const artisanOnly = async (req, res, next)=>{
    if (!req.artisanId || !req.artisanUsername) return res.status(403).json({message:" Sorry! Strictly for artisans"})
    next()
}







export { 
    authenticateAccessToken, verifyRefreshAccessToken, requireSuperuser,
    adminOnly, customerOnly, artisanOnly
}
























