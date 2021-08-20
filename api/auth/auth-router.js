const router = require('express').Router();
const bcrypt = require('bcryptjs');
const Users = require('../users/users-model');
const rmw = require('../middleware/register'); 
const lmw = require('../middleware/login');
const tokenBuilder = require('./tokenBuilder');

router.post('/register', rmw.checkBody, async (req, res, next) => {
  try{
    let user = req.body
    const rounds = process.env.ROUNDS || 8
    const hash = bcrypt.hashSync(user.password, rounds)
    user.password = hash

    const newUser = await Users.addUser(user) 
    res.status(201).json(newUser)
  } catch(err) {
    next(err)
  }
});
  router.post('/login', lmw.checkBody, async (req, res, next) => {
    try {
      let { password } = req.body
      if(req.user && bcrypt.compareSync(password, req.user.password)) {
        const token = tokenBuilder(req.user)
        res.status(200).json({ message: `welcome, ${req.user.username}`, token })
      } else {
        res.status(401).json({ message: "invalid credentials" })
      }
    } catch(err) {
      next(err)
    }
  });


module.exports = router;
