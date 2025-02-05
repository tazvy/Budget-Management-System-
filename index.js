var express = require("express");
var cors = require("cors");

var app = express();


const nodemailer = require("nodemailer");

app.use(cors());

var mysql = require("mysql");

var bodyParser = require("body-parser");
const { versions } = require("process");



// Generate a salt for hashing


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json({ limit: "50mb" }));

app.set("view engine", "ejs");

var conn = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "bilal",
});

conn.connect(function (err) {
  if (err) throw err;

  console.log("Connection Sucessful");
});

app.post("/Get", function (req, res) {
    var email = req.body.email;
    var password = req.body.password;
  
    
  
   
  
    var sql = "SELECT * FROM login WHERE email = ? AND password = ?";
    conn.query(sql, [email, password], function (err, results) {
      
      if (err) {
        console.error(err);
        res.sendStatus(500);
      } else {
        res.json(results);
      }
    });
  });

  app.post("/registeruser", function (req, res) {
    
  
    var name = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    var location = req.body.location;
    
    console.log(name);
   
   
    // Get the file path of uploaded image
  
    var sql = `insert into login values ('','${name}' , '${password}','${email}', '${location}')`;
  
    conn.query(sql, function (err, results) {
      if (err) throw err;
  
      res.send("<h1>Data Inserted.</h1>");
    });
  });


  app.post("/insert", function (req, res) {
    
  
    var name = req.body.name;
    var password = req.body.catagory;
    var email = req.body.cost;
    var location = req.body.date;
    
    console.log(name);
   
   
    // Get the file path of uploaded image
  
    var sql = `insert into thingstrack values ('','${name}' , '${password}','${email}', '${location}')`;
  
    conn.query(sql, function (err, results) {
      if (err) throw err;
  
      res.send("<h1>Data Inserted.</h1>");
    });
  });
  
  app.post("/totalbudget", function (req, res) {
    
  
    var amount = req.body.amount;
  
   
    var sql = `UPDATE totalbudget SET amount = ${amount} WHERE ID = 1`;

    
  
    conn.query(sql, function (err, results) {
      if (err) throw err;
  
      res.send("<h1>Data Inserted.</h1>");
    });
  });

  app.post("/deletethings", function (req, res) {
    
  
    var Title = req.body.pname;
  
   
    var sql = "DELETE FROM thingstrack WHERE Title = ?";

    
  
    conn.query(sql, [Title], function(err, result) {
      if (err) throw err;
  
      res.send("<h1>Data Inserted.</h1>");
    });
  });


  app.post("/update", function (req, res) {
    
  
    var name = req.body.name;
  var cost=req.body.cost;
  var catagory=req.body.catagory;
  var parentname=req.body.parentname;
  var date=req.body.date;
   
  console.log(parentname);
  var sql = "UPDATE thingstrack SET Title = ?, Cost = ?,Date = ?,Catagory = ? WHERE Title = ?";

  // Execute the query with parameters
  conn.query(sql, [name, cost,date,catagory, parentname], function(err, result) {
      if (err) throw err;
  
      res.send("<h1>Data Inserted.</h1>");
    });
  });


  app.get("/Getbudget", function (req, res) {
    var sql = "SELECT * FROM totalbudget where ID=1";
  
    conn.query(sql, function (err, results) {
      // handle the query results here
      if (err) {
        console.error(err);
        res.sendStatus(500);
      } else {
       
        res.json(results);
      }
    });
  });

  app.get("/Getthings", function (req, res) {
    var sql = "SELECT * FROM thingstrack";
  
    conn.query(sql, function (err, results) {
      // handle the query results here
      if (err) {
        console.error(err);
        res.sendStatus(500);
      } else {
       
        res.json(results);
      }
    });
  });

  app.get("/GetReport", function (req, res) {
    var sql = "SELECT * FROM reports ORDER BY ID DESC";
  
    conn.query(sql, function (err, results) {
      // handle the query results here
      if (err) {
        console.error(err);
        res.sendStatus(500);
      } else {
        res.json(results);
      }
    });
  });


  app.post("/email", function (req, res) {

    var email =req.body.email;
    var name=req.body.name;
    results={email:email};
    
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "f201023@cfd.nu.edu.pk",
        pass: "03074659133",
      },
    });
  
  
  
    const mailOptions = {
      from: "f201023@cfd.nu.edu.pk",
      to: email,
      subject: "Authentication Code",
      text: `Hy ${name},\n\nYou are recently login to your Budget planner account\n\nif you found it unsispecious then check your account,\nelse ignore the mail`,
    };
  
    
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
        res.status(500).send("Failed to send email.");
      } else {
       
        res.json(results);
      }
    });
  
      
  });

  var server = app.listen(4000, function () {
    console.log("App running on port 4000");
  });