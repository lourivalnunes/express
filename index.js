const express = require('express')
const { validate, ValidationError, Joi } = require('express-validation')
const { Pool } = require('pg')
const { compare, genSalt, hash } = require('bcryptjs') // Importar as funções do bcryptjs
//const { user } = require('pg/lib/defaults')
const asyncHandler = require('express-async-handler')
const crypto = require('crypto'); // Importar o módulo crypto
const nodemailer = require('nodemailer')
const { password } = require('pg/lib/defaults')



const pool  = new Pool({
    host: 'mel.db.elephantsql.com',
    port: 5432,
    database: 'vrkczget',
    user: 'vrkczget',
    password: '8YFmZV3ZNUswt76tKKZBWgvhWnUWFUHX',
    max: 10,
    idleTimeoutMillis: 4000,
    connectionTimeoutMillis: 30000,
    })

const app = express()
app.use(express.json());
const port = 3000

app.get('/', (req, res) => {
    res.json('Hello world!')
})

const accountInputValidation = {
    body: Joi.object({
        name: Joi.string().min(3).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
    })
}
app.post('/account', validate(accountInputValidation), async (req,res) =>{
    const input = req.body;

    const client = await pool.connect()

    const salt = await genSalt(10); // Gerar o salt
    const hashedPassword = await hash(input.password, salt); // Criptografar a senha

    function randomCode(length = 6) {
        let code = ''
        for (let i = 0; i < length; i++) {
          code += Math.floor(Math.random() * 10)
        }
        return code;
      }

      const confirmationCode = randomCode()

    const result = await client.query('INSERT INTO account (name, email, password, confirmationcode) VALUES ($1, $2, $3, $4) RETURNING *',[
    input.name,
    input.email,
    hashedPassword,
    confirmationCode
   ])

    client.release()

   const createdAccount = result.rows[0]

   return res.json(createdAccount)   
})

const loginInputValidation = {
    body: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(6).required(),
    })
}
app.post('/login', validate(loginInputValidation), async (req,res) =>{
    const input = req.body;

    const client = await pool.connect()
    
    const result = await client.query('SELECT * FROM account  WHERE email = $1', [
    input.email
   ])

   client.release()

   if(result.rows.length == 0){
    return res.status(400).json({message: 'Invalid email or password'})
   }

   const account = result.rows[0]

   if(account.confirmed === false){
    return res.status(400).json({message: 'Verify your email to confirm you account'})
   }

   const match = await compare(input.password, account.password)
   if (match){
    //senha correta
    delete account.password;
    return res.json(account)
   } else {
    //senha incorreta
    return res.status(400).json({ message: 'Invalid email or password'})
   } 
})

const confirmationCodeInputValidation = {
  body: Joi.object({
    email: Joi.string().email().required(),
    confirmationCode: Joi.string().required(),
  })
}
app.post('/confirmationCode', validate (confirmationCodeInputValidation), async (req, res) => {
  const input = req.body;
  
  const client = await pool.connect()
  
  const result = await client.query('SELECT * FROM account WHERE email = $1 AND confirmationcode = $2', [
    input.email,
    input.confirmationCode
  ])

  if (result.rows.length === 0) {
    return res.status(400).json({ message: 'Invalid email or confirmation code' })
  }
  
  const account = result.rows[0]
  
  if (account.confirmed === true) {
    return res.status(400).json({ message: 'User confirmed' })
  }     
  
  await client.query('UPDATE account SET confirmed = true WHERE email = $1 AND confirmationcode = $2', [
    input.email,
    input.confirmationCode]) 

  client.release()

  return res.json(true)
})

app.post('/forgot_password', asyncHandler(async (req, res) => {
  const { email } = req.body
  
  const client = await pool.connect()
  
  const result = await client.query('SELECT * FROM account WHERE email = $1', [
  email,
  ])
  
  if (result.rows.length === 0) {
  return res.status(400).json({ error: 'User not found in our database' })
  }
  
  const account = result.rows[0]
  
  const token = crypto.randomBytes(20).toString('hex')
  const now = new Date()
  now.setHours(now.getHours() + 1)
 
  await client.query('UPDATE account SET passwordresettoken = $1, passwordresetexpires = $2 WHERE email = $3', [
    token,
    now,
    email,
    ])
    

  }))
  app.post('/reset_password', asyncHandler(async (req, res) => {
  const { email, token, password } = req.body;
  
  const client = await pool.connect()
  
  const result = await client.query('SELECT * FROM account WHERE email = $1 AND passwordresettoken = $2', [
  email,
  token,
  ])
  
  if (result.rows.length === 0) {
  return res.status(400).json({ error: 'Invalid email or token' })
  }
  
  const account = result.rows[0];

  const now = new Date();
  if (now > account.passwordresetexpires) {
  return res.status(400).json({ error: 'Token has expired, please generate a new one' })
  }
  
  const salt = await genSalt(10)
  const hashedPassword = await hash(password, salt)
  
  await client.query('UPDATE account SET password = $1, passwordresettoken = null, passwordresetexpires = null WHERE email = $2', [
  hashedPassword,
  email,
  ])
  
  client.release()
  
  return res.status(200).json({ status: 'Password changed successfully' })
  }))
app.use(function(err,req,res,next) {
    if (err instanceof ValidationError) {
        return res.status(400).json(err)
    }
    return res.status(500).json(err)
})

app.listen(port, () => {
    console.log(`App listening on port ${port}`)
})
