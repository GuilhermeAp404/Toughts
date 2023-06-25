const User = require('../models/User')

const bcrypt = require('bcryptjs')
const { use } = require('../routes/authRoutes')

module.exports = class AuthController{
    static login(req, res){
        res.render('auth/login')
    }

    static async loginPost(req, res){
        const {email, password} = req.body

        //find user
        const user = await User.findOne({where: {email: email}})

        if(!user){
            req.flash('messsage', 'Usuario não encontrado')
            res.render('auth/login')

            return
        }

        const passwordMatch = bcrypt.compareSync(password, user.password)

        if(!passwordMatch){
            req.flash('messsage', ' Senha inválida!')
            res.render('auth/login')

            return
        }

        req.session.userid = user.id

        req.flash('message', 'Autenticação feita com sucesso!')
        
        req.session.save(() => {
            res.redirect('/')
        })

    }

    static register(req, res){
        res.render('auth/register')
    }

    static async registerPost(req, res){
        const {name, email, password, confirmpassword} = req.body

        //pwd validation
        if(password!=confirmpassword){
            req.flash('message', 'As senhas não conferem')
            res.render('auth/register')
            
            return
        }

        //check user existis
        const checkUserExists = await User.findOne({where:{email:email}})
        if(checkUserExists){
            req.flash('message', 'O e-mail já está em uso')
            res.render('auth/register')

            return
        }

        //create pwd
        const salt = bcrypt.genSaltSync(10)
        const hashedPassword = bcrypt.hashSync(password, salt)

        const user={
            name,
            email,
            password: hashedPassword
        }
        

        try{
            const userCreated = await User.create(user)

            req.session.userid = userCreated.id

            req.flash('message', 'Cadastro realizado com sucesso!')
            
            req.session.save(() => {
                res.redirect('/')
            })

        }catch(err){
            console.log(err)
            res.redirect('/register')
        }
    }

    static logout(req, res){
        req.session.destroy()
        res.redirect('/login')
    }
}