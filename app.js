require('dotenv').config();

const config = {

    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME,
    username: process.env.DB_USER,
    password: process.env.DB_PASS,

};

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const passport = require('passport');


const Sequelize = require('sequelize');
const UserModel = require('./database/models/user');
const ProductModel = require('./database/models/product');
const OrderModel = require('./database/models/order');
const OrderProductModel = require('./database/models/order_product');

// load passport configuration middleware
const { passportLoginRoute, passportJWTStrategy } = require('./middleware/passport-config');

const connectionString = `postgres://${config.username}:${config.password}@${config.host}:${config.port}/${config.database}`
const sequelize = new Sequelize(process.env.DATABASE_URL || connectionString, {

    dialect: 'postgres',
    pool: {
        max: 10,
        min: 0,
        acquire: 30000,
        idle: 10000
    }

})

console.log(connectionString);

const Users = UserModel(sequelize, Sequelize);
const Products = ProductModel(sequelize, Sequelize);
const Orders = OrderModel(sequelize, Sequelize);
const OrderProducts = OrderProductModel(sequelize, Sequelize);

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cors());
app.use(express.static('public'));

// init passport with passportJWTStrategy
passportJWTStrategy({ passport, Users });
// add login route
passportLoginRoute({ app, Users });


// API get all users
app.get('/api/users/', (req, res) => {

    Users.findAll().then((results) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(results));
    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Users');
    })

});

// API get target user
app.get('/api/users/:id', (req, res) => {

    let id = req.params.id;

    Users.findOne({ where: { id: id } }).then(results => {

        if (results) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('User does not exist is DB');
        }

    }).catch((e) => {
        console.log(e);
        res.status(434).send('error retrieving info on target User');
    })

});

// API add user
app.post('/api/users/register', (req, res) => {

    //default admin to false if req.body.admin is null
    if (req.body.admin == null) {
        req.body.admin = false;
    }

    const data = {
        f_name: req.body.f_name.trim(),
        l_name: req.body.l_name.trim(),
        email: req.body.email.toLowerCase().trim(),
        phone: req.body.phone,
        password: req.body.password.trim(),
        admin: req.body.admin,
    };


    if (data.f_name && data.l_name && data.email && data.password) {

        var salt = bcrypt.genSaltSync(10);
        var hash = bcrypt.hashSync(data.password, salt);
        data.password = hash;

        Users.create(data).then((user) => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(user));
        });

    } else {

        res.status(434).send('First and Last name, email, and password are required to register')

    }

});

// API update a target user's info
app.put('/api/users/:id', function (req, res) {

    const data = {

        id: req.params.id,
        f_name: req.body.f_name.trim(),
        l_name: req.body.l_name.trim(),
        email: req.body.email.toLowerCase().trim(),
        phone: req.body.phone,
        password: req.body.password.trim(),
        admin: req.body.admin

    };

    Users.findOne({ where: { id: data.id } }).then(user => {

        if (data.password != null) {

            var salt = bcrypt.genSaltSync(10);
            var hash = bcrypt.hashSync(data.password, salt);
            data.password = hash;

        }

        user.update({

            f_name: data.f_name,
            l_name: data.l_name,
            email: data.email,
            phone: data.phone,
            password: data.password,
            admin: data.admin

        }).then(function (newData) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(newData));
        }).catch(function (e) {
            res.status(434).send('unable to update User')
        })

    }).catch(function (e) {
        console.log(e);
        res.status(434).send(`unable to find User ${data.id}`)

    })

});

// API delete target User
app.delete('/api/users/:id', (req, res) => {

    const id = req.params.id;

    Users.findOne({ where: { id: id } }).then(user => {

        user.destroy().then(() => {

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(user));

        }).catch((e) => {

            console.log(e);
            res.status(434).send('unable to delete User')

        })

    }).catch((e) => {

        console.log(e);
        res.status(434).send('error retrieving info on target User');

    })

});

// API get all products
app.get('/api/products/', function (req, res) {

    Products.findAll().then((results) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(results));
    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Products');
    })

});

// API get all products by type
app.get('/api/products/type/:id', function (req, res) {

    const id = req.params.id;

    Products.findAll({ where: { type_id: id } }).then((results) => {

        if (results.length != 0) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('No products found belonging to this type!');
        }

    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Products of this type');
    })

});

// API get all products by category
app.get('/api/products/category/:id', function (req, res) {

    const id = req.params.id;

    Products.findAll({ where: { category_id: id } }).then((results) => {

        if (results.length != 0) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('No products found belonging to this category!');
        }

    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Products of this category');
    })

});

// API get target product
app.get('/api/products/:id', function (req, res) {

    let id = req.params.id;

    Products.findOne({ where: { id: id } }).then(results => {

        if (results) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('Product not found');
        }

    }).catch(function (e) {
        console.log(e);
        res.status(434).send('error retrieving info on target Product');
    })

});

// API add product
app.post('/api/products/register', function (req, res) {

    const data = {

        name: req.body.name,
        type_id: req.body.type_id,
        category_id: req.body.category_id,
        description: req.body.description,
        quantity: req.body.quantity,
        price: req.body.price,
        image_url: req.body.image_url

    };


    if (data.name && data.type_id && data.category_id && data.description && data.quantity && data.price && data.image_url) {

        Products.create(data).then(product => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(product));
        }).catch((e) => {
            console.log(e);
            res.status(434).send('error registering Product');
        })

    } else {

        res.status(434).send('All fields are required to register.')

    }

});

// API update a target product's info
app.put('/api/products/:id', function (req, res) {

    const data = {

        id: req.params.id,
        name: req.body.name,
        type_id: req.body.type_id,
        category_id: req.body.category_id,
        description: req.body.description,
        quantity: req.body.quantity,
        price: req.body.price,
        image_url: req.body.image_url

    };

    Products.findOne({ where: { id: data.id } }).then(product => {

        product.update({

            name: data.name,
            type_id: data.type_id,
            category_id: data.category_id,
            description: data.description,
            quantity: data.quantity,
            price: data.price,
            image_url: data.image_url,

        }).then(newData => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(newData));
        }).catch((e) => {
            res.status(434).send('unable to update Product')
        })

    }).catch((e) => {
        console.log(e);
        res.status(434).send(`unable to find Product ${data.id}`)

    })

});

// API delete target Product
app.delete('/api/products/:id', (req, res) => {

    const id = req.params.id;

    Products.findOne({ where: { id: id } }).then(product => {

        product.destroy().then(() => {

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(product));

        }).catch((e) => {

            console.log(e);
            res.status(434).send('unable to delete Product')

        })

    }).catch((e) => {

        console.log(e);
        res.status(434).send('error retrieving info on target Product');

    })

});

// API get all orders
app.get('/api/orders/', (req, res) => {

    Orders.findAll().then((results) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(results));
    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Orders');
    })

});

// API get target order
app.get('/api/orders/:id', function (req, res) {

    let id = req.params.id;

    Orders.findOne({ where: { id: id } }).then(results => {

        if (results) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('Order does not exist is DB');
        }

    }).catch(function (e) {
        console.log(e);
        res.status(434).send('error retrieving info on target Order');
    })

});

// API get all orders made by target User
app.get('/api/orders/user/:id', function (req, res) {

    const id = req.params.id;

    Orders.findAll({ where: { user_id: id } }).then((results) => {

        if (results.length != 0) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send(`No orders have been made by user ${id}!`);
        }

    }).catch(function (e) {
        console.log(e);
        res.status(434).send('User does not exist');
    })

});

// Register an Order
/*

{
    user_id: 1,
    quantity: 5,
    price: 500,
    purchase_date: new Date(),
    order_products: [
        {product_id: 3, quantity: 10, price: 400},
        {product_id: 3, quantity: 10, price: 400},
        {product_id: 3, quantity: 10, price: 400}
    ]
}

*/
app.post('/api/orders/register', function (req, res) {

    const data = {

        user_id: req.body.user_id,
        quantity: req.body.quantity,
        price: req.body.price,
        purchase_date: new Date(),

    };

    if (data.user_id && data.purchase_date && data.quantity && data.price) {

        Orders.create(data).then((order) => {

            req.body.order_products.forEach(product => {

                product.order_id = order.id;
                OrderProducts.create(product);

            });

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(order));

        }).catch((e) => {

            console.log(e);
            res.status(434).send('error registering Order');

        })

    } else {

        res.status(434).send('All fields are required to register an Order.');

    }

});

/* API update a target order's info

*/

app.put('/api/orders/:id', function (req, res) {

    const data = {

        id: req.params.id,
        user_id: req.body.user_id,
        quantity: req.body.quantity,
        price: req.body.price

    };

    Orders.findOne({ where: { id: data.id } }).then(order => {

        order.update({

            user_id: data.user_id,
            quantity: data.quantity,
            price: data.price

        }).then(newData => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(newData));
        }).catch((e) => {
            res.status(434).send('unable to update Order')
        })

    }).catch((e) => {
        console.log(e);
        res.status(434).send(`unable to find Order ${data.id}`)

    })

});

// API delete target Order
app.delete('/api/orders/:id', function (req, res) {

    const id = req.params.id;

    Orders.findOne({ where: { id: id } }).then(order => {

        order.destroy().then(() => {

            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(order));

        }).catch((e) => {

            res.status(434).send('unable to delete Order')

        })

    }).catch((e) => {

        console.log(e);
        res.status(434).send('error retrieving info on target Order');

    })

});

//API get all order products
app.get('/api/order-products/', (req, res) => {

    OrderProducts.findAll().then((results) => {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(results));
    }).catch(function (e) {
        console.log(e);
        res.status(434).send('Error retrieving Order Products');
    })

});

// API get target order product
app.get('/api/order-products/:id', (req, res) => {

    let id = req.params.id;

    OrderProducts.findOne({ where: { id: id } }).then(results => {

        if (results) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('Order product does not exist is DB');
        }

    }).catch((e) => {
        console.log(e);
        res.status(434).send('error retrieving info on target Order product');
    })

});

// API get all products of target order
app.get('/api/order-products/order/:id', (req, res) => {

    const id = req.params.id;

    OrderProducts.findAll({ where: { order_id: id } }).then((results) => {

        if (results.length != 0) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(results));
        } else {
            res.status(434).send('No products found belonging to this order!');
        }

    }).catch((e) => {
        console.log(e);
        res.status(434).send('Error retrieving Products of this order');
    })

});

// API get all order products of target user
app.get('/api/order-products/user/:id', (req, res) => {

    const id = req.params.id;

    Orders.findAll({ where: { user_id: id } }).then((orders) => {

        if (orders.length != 0) {

            let userOrderProducts = [];

            let promise = new Promise(() => {

                orders.forEach(order => {

                    OrderProducts.findAll({

                        where: { order_id: order.id }

                    }).then(results => {

                        results.forEach(product => userOrderProducts.push(product))

                    }).catch((e) => {

                        console.log(e);
                        res.status(434).send('Error retrieving Products of this order');

                    });

                })
                    .then(() => {

                        res.setHeader('Content-Type', 'application/json');
                        res.end(JSON.stringify(userOrderProducts));

                    })
                    .catch((e) => {
                        console.log(e);
                        res.status(434).send('Error retrieving Products of this User');
                    })
            });

        } else {

            console.log(e);
            res.status(434).send('No products found belonging to this user!');

        }

    }).catch((e) => {

        console.log(e);
        res.status(434).send('Error retrieving Products belonging to this user');

    });

});


const port = process.env.PORT || 3001;
app.listen(port, () => { console.log(`Drinks-R-Us API is running. app listening on port ${port}`); });