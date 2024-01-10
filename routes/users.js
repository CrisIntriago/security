var express = require('express');
var router = express.Router();


/*Módulo jsonwebtoken*/
const jwt = require("jsonwebtoken");


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
    })

    try {
      await UsersRoles.create({ users_iduser: user.iduser, roles_idrole: role.idrole })
    } catch (error) {
      console.log("Big error here and I don't know why");
    }


    res.redirect("/users");

  } catch (error) {
    res.status(400).send(error);
  }

});


/* GET users listing. */
router.get('/', async function (req, res, next) {
  let users = await Users.findAll({});
  res.render("register", { title: "User Registration", users: users });
});



router.post("/generateToken", async (req, res, next) => {
  let { name, password } = req.body;

  try {
    /*encriptamos la contraseña */
    let salt = process.env.SALT;
    let hash = crypto.createHmac("sha512", salt).update(password).digest("base64");
    let passwordHash = salt + "$" + hash

    /*Obtenemos el usuario y su rol*/
    let user = await Users.findOne({ where: { [Op.and]: [{ name: name }, { password: passwordHash }] } })
    let relations = await UsersRoles.findOne({ where: { [Op.and]: [{ users_iduser: user.iduser }] } });
    let roles = await Roles.findOne({ where: { [Op.and]: [{ idrole: relations.roles_idrole }] } });


    const accessToken = jwt.sign({ name: user.name, role: roles.name }, process.env.TOKEN_SECRET);

    res.json({ accessToken });

  } catch (error) {
    res.status(400).send(error);
  }




});



module.exports = router;
