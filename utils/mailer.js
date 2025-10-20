import dotenv from 'dotenv'
import Mailgun from 'mailgun.js'
import FormData from 'form-data'

dotenv.config()

const mailgun = new Mailgun(FormData)

const mg = mailgun.client({
  username : "api",
  key : process.env.MAILGUN_API_KEY
})

const sendOtpEmail = async (toEmail, otp) => {
  try{
    const msg = await mg.messages.create(process.env.MAILGUN_DOMAIN,{
    from: `"Stitch Support" <postmaster@${process.env.MAILGUN_DOMAIN}>`,
    to: [toEmail],
    subject: "Your OTP for Password Reset",
    html: `<h3>Hello from Stitch!</h3><p>Your OTP is: <strong>${otp}</strong>. 
        It expires in 5 minutes.</p>`
  })
  }catch(err){
    console.log("Error sending email", err.stack)
    throw err
  }
  
};

export default sendOtpEmail ;
