const express = require('express');
require("dotenv").config();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('./middleware/auth');

const app = express();


app.use(express.urlencoded({
    extended: false
 }));
app.use(express.json());
app.use('/', express.static(path.join(__dirname,'./public')));
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Cookie, Origin, X-Requested-With, Content-Type, Accept, x-auth-token");
    res.header("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Credentials", true);
    next();
  });

app.get('/api/categories', auth, function(req, res) {
  if (req.query.id !== undefined){
    CategoryModel.findOne({_id: req.query.id}).exec(function(err, result) {
        res.send(result);
    });
  } else {
    CategoryModel.find().exec(function(err, result) {
        res.send(result);
    });
  }
});

app.get('/api/questions', auth, function(req, res) {
    if (req.query.category !== undefined){
        QuestionModel.find({category: req.query.category})
        .populate('author', 'username')
        .populate('category', 'label')
        .select('-answers')
        .exec(function(err, result) {
            res.send(result);
        });
    } else res.send([]);
});

app.post('/api/questions', auth, function(req, res) {  
  CategoryModel.findOne({label: req.body.category})
  .then(category=> {
    if (!category) {
      var newCategory = new CategoryModel({_id: new mongoose.Types.ObjectId(),
        label: req.body.category
        });
      newCategory.save((err, category) => saveNewQuestion(req, res, category));
    } else {
      saveNewQuestion(req, res, category);
    }
  });
});

const saveNewQuestion = (req, res, category) => {
  var newQuestion = new QuestionModel({_id: new mongoose.Types.ObjectId(),
    label: req.body.label,
    author: req.body.authorId,
    category: category._id,
    answers: req.body.answers.reduce((acc, answer) => acc.set(answer, 1), new Map())
    });
  newQuestion.save((err, newElement) => {
    if (err) {
      console.log('save error ', err);
      if (err.name === 'MongoError' && err.code === 11000) {
        res.json({success: false, message: 'already exists'});
        return;
      }
      res.json({success: false, message: 'some error happened'});
      return;
    }
    res.send(newElement);   
  });
}

app.put('/api/questions/:id', auth, function(req,res){
  QuestionModel.findById(req.params.id).exec((err, question) => {
    if (err) {
      console.log('question not found', err);
      res.send();
    }
    let answer = req.body.answer.charAt(0).toUpperCase() + req.body.answer.slice(1).toLowerCase();
    let answerCount = (question.answers.get(answer) || 0) + 1;
    let sortedMap = [...question.answers.toObject().entries()].sort((a, b) => b[1] - a[1]);
    let index = sortedMap.findIndex(element => element[0] === answer);
    question.answers.set(answer, answerCount)
    question.save()
    .then(question => {
      let newSortedMap = [...question.answers.toObject().entries()].sort((a, b) => b[1] - a[1]);
      let newIndex = newSortedMap.findIndex(element => element[0] === answer);
      if (newIndex < 0) {
        throw("Index should have been found")
      } else if (newIndex < 5) {
        let totalAnswer = newSortedMap.reduce((acc, array) => acc + array[1], 0);
        if (newIndex === index) {
          res.send({success: true, answer, index, answerCount, totalAnswer});
        } else {
          res.send({success: true, answer, index, newIndex, answerCount, totalAnswer});
        }
      } else {
        res.send({success: false});
      }
    }).catch(err => console.log('modification error ', err));
  });   
});

app.put('/api/users/:id', auth, function(req,res){
  UserModel.findByIdAndUpdate(req.params.id).exec((err, user) => {
    if (err) {
      console.log('user not found', err);
      res.send();
    }
    const {likedQuestion, bookmarkedCategory} = req.body;
    if (likedQuestion) {
      if (user.likedQuestions.includes(likedQuestion)) {
        user.likedQuestions.pull(likedQuestion);
      } else {
        user.likedQuestions.push(likedQuestion);
      }
    } else if (bookmarkedCategory){
      if (user.bookmarkedCategories.includes(bookmarkedCategory)) {
        user.bookmarkedCategories.pull(bookmarkedCategory);
      } else {
        user.bookmarkedCategories.push(bookmarkedCategory);
      }
    }
    user.save();
  });
});

var mongoose = require('mongoose');
    mongoose.set('debug',true);
    mongoose.connect(`mongodb+srv://${process.env.MONGO_USERNAME}:${process.env.MONGO_PASSWORD}@cluster0.xorwi.mongodb.net/guess-words?retryWrites=true&w=majority`);
    mongoose.Promise = Promise;

var db = mongoose.connection;
db.on('error', function(e) {
    console.error('connection error:', e);
});

var CategoryModel;
var QuestionModel;
var UserModel;
db.once('open', function(callback) {
    const Schema = mongoose.Schema;

    const categorySchema = new Schema({
        _id: Schema.Types.ObjectId,
        label: String
    });
    CategoryModel = mongoose.model('Category', categorySchema);
    
    const userSchema = new Schema({
        _id: Schema.Types.ObjectId,
        username: {type: String, required: true},
        password: {type: String, required: true},
        likedQuestions:[{type: Schema.Types.ObjectId, ref: 'Question' }],
        bookmarkedCategories:[{type: Schema.Types.ObjectId, ref: 'Category' }],
    });
    UserModel = mongoose.model('User', userSchema);

    const questionSchema = new Schema({
        _id: Schema.Types.ObjectId,
        label: String,
        author: { type: Schema.Types.ObjectId, ref: 'User' },
        category: { type: Schema.Types.ObjectId, ref: 'Category' },
        answers: {
          type: Map,
          of: Number
        }
    });
    QuestionModel = mongoose.model('Question', questionSchema);

    // the connection to the DB is okay, let's start the application
    const httpServer = app.listen(process.env.PORT || 3001, () => {
        console.log(`Example app listening on port ${process.env.PORT || 3001}!`);
    }); 
   
    //register
    app.post('/api/users', function(req, res) {
        const {username, password} = req.body;
        if (!username || !password){
            return res.status(400).json({msg: 'Please enter all fields'});
        }
        UserModel.findOne({username})
            .then(user=>{
                if(user) return res.status(400).json({msg: 'User alreasy exists'});
            })
        const newUser = new UserModel({
            _id: new mongoose.Types.ObjectId(),
            username,
            password,
            likedQuestions: [],
            bookmarkedCategories: []
        });
        // Create salt & hash
        bcrypt.genSalt(10, (err, salt) =>{
            bcrypt.hash(newUser.password, salt, (err, hash) =>{
                if (err) throw err;
                newUser.password = hash;
                newUser.save()
                    .then(newUser => {
                      let user = newUser.toObject();
                        if (err) {
                            console.log('save error ', err);
                            if (err.name === 'MongoError' && err.code === 11000) {
                                // Duplicate error happened. You can handle it separately.
                                res.json({success: false, message: 'already exists'});
                                return;
                            }
                            // Some other error happened, you might also want to handle it.
                            res.json({success: false, message: 'some error happened'});
                            return;
                        }
                        
                        jwt.sign(
                            {_id:user._id},
                            process.env.JWT_SECRET,
                            {expiresIn: 3600},
                            (err, token) =>{
                                if(err) throw err;
                                delete user.password;
                                res.json({token,user});
                            }
                        )
                        
                    })
            })
        })
    });

    //login
    app.post('/api/auth', function(req, res) {
        const {username, password} = req.body;
        if (!username || !password){
            return res.status(400).json({msg: 'Please enter all fields'});
        }
        UserModel.findOne({username}).lean()
            .then(user=>{
                if(!user) return res.status(400).json({msg: 'User does not exist'});

                //Validate password
                bcrypt.compare(password, user.password)
                    .then(isMatch =>{
                        if(!isMatch) return res.status(400).json({msg: 'Invalid credentials'});

                        jwt.sign(
                            {_id:user._id},
                            process.env.JWT_SECRET,
                            {expiresIn: 3600},
                            (err, token) => {
                                if(err) throw err;
                                delete user.password;
                                res.json({token,user});
                            }
                        )
                    })
            })
    });
    app.get('/api/auth/user', auth, function(req, res) {
        UserModel.findById(req.user._id)
        .select('-password')
        .then(user => res.json({user}));
    });
});