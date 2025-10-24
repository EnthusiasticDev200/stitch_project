import db from '../../config/database.js'
import { hash, verify } from 'argon2'
import redis from '../../config/redis.js'
import generateToken from '../../../utils/token.js'
import createOtp from '../../../utils/otp.js'
import otpQueue from '../../../utils/worker.js'



const existingUsernameAndEmails = async (email,username) =>{
    const [isAdmin, isArtisan, isCustomer] = await Promise.all([
        db.query(`SELECT email, username FROM admins WHERE email = $1 OR username = $2`,[email, username]),
        db.query(`SELECT email, username FROM artisans WHERE email = $1 OR username = $2`,[email, username]),
        db.query(`SELECT email, username FROM customers WHERE email = $1 OR username = $2`,[email, username]),
    ])
    const admin = isAdmin.rows[0]
    const artisan = isArtisan.rows[0]
    const customer = isCustomer.rows[0]

    const isExisting = admin || artisan || customer
    return isExisting;
}

// const existingUserEmail = async ( email) =>{
//     const [isAdmin, isArtisan, isCustomer] = await Promise.all([
//         db.query(`SELECT email, username FROM admins WHERE email = $1 `,[email]),
//         db.query(`SELECT email, username FROM artisans WHERE email = $1`,[email]),
//         db.query(`SELECT email, username FROM customers WHERE email = $1`,[email]),
//     ])
//     const admin = isAdmin.rows[0]
//     const artisan = isArtisan.rows[0]
//     const customer = isCustomer.rows[0]

//     const [adminEmail, artisanEmail, customerEmail] = admin || artisan || customer
//     console.log('adminEmail, artisanEmail, customerEmail', adminEmail, artisanEmail, customerEmail)
//     return adminEmail, artisanEmail, customerEmail;
// }


const createAdmin = async(req,res)=>{
    try{
        const {username, email, phoneNumber, password, role} = req.body;
        //set password
        const hashedPassword = await hash(password)
        const isExistingUser = await existingUsernameAndEmails(email, username)
        
        if ( !isExistingUser ){
            //create record
            await db.query(`
                INSERT INTO admins (username, email, phone_number, password_hash, role)
                VALUES ($1, $2, $3, $4, $5)`, 
                [username, email, phoneNumber, hashedPassword, role])
            return res.status(201).json({ message : 'Admin created successfully' })
        }
        const existingUsername = isExistingUser.username
        const existingEmail = isExistingUser.email

        if ( existingEmail === email ) return res.status(409).json({ message: 'Email already used'}) 
        
        if ( existingUsername === username ) return res.status(409).json({ message: 'Username already used'}) 
    }catch(err){
        console.log("Error registering admin", err.stack)
        return res.status(500).json({
            message : "Admin registration failed",
            error : err.message
        })
    }
}

const loginAdmin = async (req, res) =>{
    try{
        const { email, password } = req.body
        
        const admin = await db.query(`
            SELECT admin_id, username, role, password_hash FROM admins WHERE email = $1`, [email])
        if (admin.rows.length === 0) return res.status(404).json({
            message : " Invalid email"
        })
        const beforeHash = performance.now()
        const passwordMatch = await verify(admin.rows[0].password_hash, password)
        const afterHash = performance.now() - beforeHash
        console.log('Total hashTime', afterHash)

        if ( !passwordMatch ) return res.status(401).json({
            message : "Wrong password"})
        // set up jwt
        const payload = {
            adminId : admin.rows[0].admin_id,
            adminUsername : admin.rows[0].username,
            role : admin.rows[0].role
        }
        const adminToken = generateToken.accessToken(payload)
        res.clearCookie('admin_token')
        res.cookie('admin_token', adminToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 5 * 60 * 1000

        })
        const refreshPayload = {
            adminId : admin.rows[0].admin_id,
            adminUsername : admin.rows[0].username,
        }
        const refreshToken = generateToken.refreshToken(refreshPayload)
        
        res.cookie('refresh_admin_token', refreshToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 12 * 60 * 60 * 1000

        })
        return res.status(200).json({
            message : `Welcome ${payload.adminUsername}`
        })
    }catch(err){
        console.log("Error login in admin", err.stack)
        return res.status(500).json({
            message : "Admin sign in failed",
            error : err.message
        })
    }
}

const logoutAdmin = ( req, res ) =>{
    const adminUsername = req.adminUsername
    try{
        if ( !adminUsername ) return res.status(401).json({
            message : "Not permitted"
        })
        res.clearCookie('admin_token')
        res.clearCookie('refresh_admin_token')
        return res.status(200).json({message : `Bye ${adminUsername}`})
    }catch(err){
       console.log("Error loggin out admin", err.stack)
        return res.status(500).json({
            message : "Admin log out failed",
            error : err.message
        }) 
    }
}

const refreshAdminToken = async ( req, res ) =>{
    const adminUsername = req.adminUsername
    try{
        const admin = await db.query(`
            SELECT admin_id, username, role FROM admins WHERE username = $1`, [adminUsername])
        if (admin.rows.length === 0) return res.status(404).json({
                message : "Invalid admin username" })
        const payload = {
            adminId : admin.rows[0].admin_id,
            adminUsername : admin.rows[0].username,
            role : admin.rows[0].role
        }
        const newAdminToken = generateToken.accessToken(payload)
        res.cookie('admin_token', newAdminToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 5 * 60 * 1000
        }) 
        return res.status(200).json({ message : `New admin token granted`})
    }catch(err){
        console.log('Error granting admin refresh token', err.stack)
        return res.status(500).json({
            message : 'Admin refresh token failed',
            error : err.message
        })
    }
}
const refreshCustomerToken = async (req, res)=>{
    const customerUsername = req.customerUsername
    try{
        const customer = await db.query(`
            SELECT customer_id, username FROM customers WHERE username = $1`, [customerUsername])
        if (customer.rows.length === 0) return res.status(404).json({
                message : "Username doesn't match" })
        const payload = {
            customerId : customer.rows[0].customer_id,
            customerUsername : customer.rows[0].username,
        }
        const newCustomerToken = generateToken.accessToken(payload)
        res.cookie('customer_token', newCustomerToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 5 * 60 * 1000
        }) 
        return res.status(200).json({ message : `New customer token granted`})
    }catch(err){
        console.log('Error granting customer refresh token', err.stack)
        return res.status(500).json({
            message : 'Customer refresh token failed',
            error : err.message
        })
    }
}

const refreshArtisanToken = async (req,res)=>{
    const artisanUsername = req.artisanUsername
    try{
        const artisan = await db.query(`
            SELECT artisan_id, username,role FROM artisans WHERE username = $1`, [artisanUsername])
        
        if (artisan.rows.length === 0) return res.status(404).json({
                message : "Invalid artisan username" })
        const payload = {
            artisanId : artisan.rows[0].artisan_id,
            artisanUsername : artisan.rows[0].username,
            artisanRole : artisan.rows[0].role
        }
        const newArtisanToken = generateToken.accessToken(payload)
        res.cookie('artisan_token', newArtisanToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 5 * 60 * 1000
        }) 
        return res.status(200).json({ message : `New artisan token granted`})
    }catch(err){
        console.log('Error granting artisan refresh token', err.stack)
        return res.status(500).json({
            message : 'Artisan refresh token failed',
            error : err.message
        })
    }
}
// CUSTOMER'S LOGIC
const createCustomer = async(req,res)=>{
    try{
        const { firstName, lastName, username, email, phoneNumber, password } = req.body;
        const hashedPassword = await hash(password)
        
        const isExistingUser = await existingUsernameAndEmails( email, username ) 
        if ( !isExistingUser ){
        //create record
            await db.query(`
                INSERT INTO customers (
                    first_name, last_name, username, email, phone_number, password_hash)
                VALUES ($1, $2, $3, $4, $5, $6)`, 
                [firstName, lastName, username, email, phoneNumber, hashedPassword])
            return res.status(201).json({ message : 'Customer created successfully' })  
        }
         
        const existingUsername = isExistingUser.username
        const existingEmail = isExistingUser.email

        if ( existingUsername === username ) return res.status(409).json({message:'Username in use'})
        if ( existingEmail === email ) return res.status(409).json({message:'Email already in use'})
        
    }catch(err){
        console.log("Error registering customer", err.stack)
        return res.status(500).json({
            message : "Customer registration failed",
            error : err.message
        })
    }
}


const loginCustomer = async (req, res) =>{
    try{
        const { email, password } = req.body
        
        const customer = await db.query(`
            SELECT customer_id, username, password_hash FROM customers WHERE email = $1`, [email])
        if (customer.rows.length === 0) return res.status(404).json({
            message : " Invalid email"
        })
        const beforeHash = performance.now()
        const passwordMatch = await verify(customer.rows[0].password_hash, password)
        const afterHash = performance.now() - beforeHash
        console.log('Total hashTime', afterHash)

        if ( !passwordMatch ) return res.status(401).json({
            message : "Wrong password"})
        // set up jwt
        const payload = {
            customerId : customer.rows[0].customer_id,
            customerUsername : customer.rows[0].username,
        }
        const customerToken = generateToken.accessToken(payload)
        res.clearCookie('customer_token')
        res.cookie('customer_token', customerToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 5 * 60 * 1000

        })
        const refreshPayload = {
            customerId : customer.rows[0].customer_id,
            customerUsername : customer.rows[0].username,
        }
        const refreshToken = generateToken.refreshToken(refreshPayload)

        res.cookie('refresh_customer_token', refreshToken,{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite :  process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
            maxAge : 12 * 60 * 60 *  1000

        })
        return res.status(200).json({
            message : `Welcome ${payload.customerUsername}`
        })
    }catch(err){
        console.log("Error login in customer", err.stack)
        return res.status(500).json({
            message : "customer sign in failed",
            error : err.message
        })
    }
}

const logoutCustomer = ( req, res ) =>{
    const customerUsername = req.customerUsername
    try{
        if ( !customerUsername ) return res.status(401).json({
            message : " Unknown customer "
        })
        res.clearCookie('customer_token')
        res.clearCookie('refresh_customer_token')
        return res.status(200).json({message : `Bye ${customerUsername}`})
    }catch(err){
       console.log("Error loggin out customer", err.stack)
        return res.status(500).json({
            message : "customer log out failed",
            error : err.message
        }) 
    }
}

const createArtisan = async( req, res ) =>{
    try{
        const {
            firstName, lastName, middleName, username, gender, dateOfBirth, address,
            email,phoneNumber,password, role } = req.body

        const hashedPassword = await hash(password)

        const isExistingUser = await existingUsernameAndEmails( email, username )
            
        if ( !isExistingUser ){
            await db.query(`
                INSERT INTO artisans(
                    first_name, last_name, middle_name, username, gender, date_of_birth, address,
                    email,phone_number,password_hash, role )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, 
                [ firstName, lastName, middleName, username, gender, dateOfBirth, address, email,
                 phoneNumber,hashedPassword, role ])
            return res.status(201).json({message: 'Artisan created successfully'})
        }
        
        const existingUsername = isExistingUser.username
        const existingEmail = isExistingUser.email
        
        if ( existingEmail === email ) return res.status(409).json({message:'Email already in use'})
        
        if ( existingUsername === username) return res.status(409).json({message:'Username in use'})
        
    }catch(err){
        console.log('Error creating artisans', err.stack)
        return res.status(500).json({
            message : "Error creating artisans",
            error : err.message
        }) 
    }
}

const loginArtisan = async (req, res) =>{
    const { email, password } = req.body
    try{
        const artisan = await db.query(`
            SELECT artisan_id, username, role, password_hash
            FROM artisans 
            WHERE email = $1`, [email])
        if ( artisan.rows.length === 0) return res.status(404).json({
            message : "Not an artisan"
        })
        // extract artisan data
        const artisanId = artisan.rows[0].artisan_id
        const artisanUsername = artisan.rows[0].username
        const artisanRole = artisan.rows[0].role
        const artisanPassword = artisan.rows[0].password_hash
        //compare password
        const passwordMatch = await verify(artisanPassword, password)
        if ( !passwordMatch ) return res.status(401).json({message: "Invalid password"})
        // create payload
        const payload = {
            artisanId : artisanId,
            artisanUsername : artisanUsername,
            artisanRole : artisanRole
        }

        const artisanToken = generateToken.accessToken(payload)
        // clear and create cookies
        res.clearCookie('artisan_token')
        res.cookie('artisan_token', artisanToken, {
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? "None" : "Lax",
            maxAge : 5 * 60 * 1000
        })
        const refreshPayload = {
            artisanId : artisanId,
            artisanUsername : artisanUsername,
        }
        const refreshToken = generateToken.refreshToken(refreshPayload)

        res.cookie('refresh_artisan_token', refreshToken, {
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? "None" : "Lax",
            maxAge : 12 * 60 * 60 * 1000
        })
        return res.status(200).json({message : `Welcome ${artisanUsername}`})
    }catch(err){
        console.group("Error logging in artisan", err.stack)
        return res.status(500).json({
            message:'Error logging in artisan',
            error : err.message
        })
    }
}

const logoutArtisan = (req, res)=>{
    try{
        const artisanUsername = req.artisanUsername
        if ( !artisanUsername ) return res.status(401).json({message:`Oops! Not granted`})
        res.clearCookie('artisan_token')
        res.clearCookie('refresh_artisan_token')
        return res.status(200).json({message: `Bye ${artisanUsername}`})
    }catch(err){
        console.log('Error logging out artisan', err.stack)
        return res.status(500).json({ message:"Logout failed", error:err.message})
    }
}

const sendOtp = async ( req, res ) =>{
    try{
        const { email } = req.body
        const [ queryAdmin, queryCustomer, queryArtisan ] = await Promise.all([
            db.query(`SELECT email FROM admins WHERE email = $1`, [email]),
            db.query(`SELECT email FROM customers WHERE email = $1`, [email]),
            db.query(`SELECT email FROM artisans WHERE email = $1`, [email]),
        ])
        const adminEmail = queryAdmin.rows[0];
        const cuustomerEmail = queryCustomer.rows[0]
        const artisanEmail = queryArtisan.email

        console.log('adminEmail', adminEmail)
        console.log('customerEmail', cuustomerEmail)
        console.log('artisanEmail', artisanEmail)

        if ( !adminEmail && !cuustomerEmail && !artisanEmail){
            return res.status(401).json('Invalid email')
        }
        // otp set-up
        const otp = createOtp()
        const otpPayload = {
            otp : otp,
            email : email,
            verified : false
        }
        await redis.set(
            `otp:${email}`,
            JSON.stringify(otpPayload),
            'EX',
            5 * 60
        )
        await otpQueue.add('send-otp-email', { email, otp }, { attempts: 3})
        return res.status(200).json({message : "OTP will be sent to your email shortly"})
    }catch(err){
        console.log('Error sending OTP', err)
        return res.status(500).json({
            message : "Error sending OTP",
            error : err.stack
        })
    }
}

const verifyOtp = async ( req, res )=>{
    try{
        const { email, inputOtp } = req.body
    
        const cachedOTP = await redis.get(`otp:${email}`)
        if ( !cachedOTP ) return res.status(401).json({message: 'OTP not found'})
       
        const otpData = JSON.parse(cachedOTP)
        if( email !== otpData.email) return res.status(401).json({
            message:'OTP not sent to this email'})
        if( inputOtp !== otpData.otp) return res.status(401).json({message:'Expired or Wrong OTP'})
        
        otpData.verified = true // otp now verified
        //update redis
        await redis.set(
           `updatedOtp:${email}`,
            JSON.stringify(otpData),
            'EX',
            5 * 60 
        )
        await redis.del(`otp:${email}`)
        return res.status(200).json({message : "OTP verified"})
    }catch(err){
        console.log("Error verifying OTP", err)
        return res.status(500).json({
            message : "Error verifying OTP",
            error : err.stack
        })
    }
}

const changePassword = async ( req, res ) =>{
    try{
        const { email, newPassword } = req.body
        const [ queryAdmin, queryCustomer ] = await Promise.all([
            db.query('SELECT email FROM admins WHERE email = $1', [email]),
            db.query('SELECT email FROM customers WHERE email = $1', [email]),
        ])
        const isAdminEmail = queryAdmin.rows.length > 0 
        const isCustomerEmail = queryCustomer.rows.length > 0 

        if( !isAdminEmail && !isCustomerEmail) return res.status(404).json({message: 'Invalid email'})

        const cachedOTP = await redis.get(`updatedOtp:${email}`)    
        if( !cachedOTP ) return res.status(401).json({message:'OTP required'})
            
        const otpData = JSON.parse(cachedOTP)
        if( email !== otpData.email ) return res.status(401).json({ message : 'Email mismatch'})
        // hash new password
        const hashedPassword = await hash(newPassword)
        //update passworda
        if( isAdminEmail) {
            await db.query(`
                UPDATE admins
                SET password_hash = $1
                WHERE email = $2`,[hashedPassword, email]
            )
            return res.status(201).json({message : 'Admin password updated'})
        }
        if( isCustomerEmail) {
            await db.query(`
                UPDATE customers
                SET password_hash = $1
                WHERE email = $2`,[hashedPassword, email]
            )
            return res.status(201).json({message : 'Admin password updated'})
        }
    }catch(err){
        console.log("Error changing password", err)
        return res.status(500).json({
            message : 'Error changing password',
            error : err.stack
        })
    }
}








export { 
    createAdmin, loginAdmin, logoutAdmin, refreshAdminToken,
    createCustomer, loginCustomer, logoutCustomer, refreshCustomerToken,
    createArtisan, loginArtisan, logoutArtisan, refreshArtisanToken,
    verifyOtp, sendOtp, changePassword
}



