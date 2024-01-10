var express = require('express');
var router = express.Router();

/* Módulo crypto */
let crypto = require("crypto");

/* Referencia a los modelos*/

const Users = require("../models").users;
const Roles = require("../models").roles;
const UsersRoles = require("../models").user_roles;
const { Op } = require("sequelize");



router.post("/register", async (req, res, next) => {
  let { name, password, roleName } = req.body;

  try {

    //Encripte la contraseña con SALT variable de .ENV
    let salt = process.env.SALT;
    let hash = crypto.createHmac("sha512", salt).update(password).digest("base64");
    let passwordHash = salt + "$" + hash

    //guarde los datos del usuario

    let user = await Users.create({ name: name, password: passwordHash });


    let role = await Roles.findOne({
      where: {
        [Op.and]: [
          { name: roleName }
        ]
      }
    });

    await UsersRoles.create({ users_iduser: user.iduser, roles_idrole: role.idrole });


    res.redirect("/users")
  
  } catch (error){
    res.status(400).send(error);
  }

});


/* GET users listing. */
router.get('/', async function (req, res, next) {
  let users = await Users.findAll({});
  res.render("register", {title:"User Registration", users: users});
});

module.exports = router;
