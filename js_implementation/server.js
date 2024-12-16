const express = require('express');
const cors = require('cors');
const WebSocket = require('ws');
const url = require('url');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');

// Create a connection to the database
const db = mysql.createConnection({
    host: 'localhost', // The host of your MySQL server
    user: 'root', // Your MySQL username (usually 'root' for local development)
    password: '', // Your MySQL password
    database: 'chat_app' // The name of your database (make sure it's 'chat_app' as created earlier)
});

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to the MySQL database');
});

// const WebSocket = require('ws');
// const wss = new WebSocket.Server({ port: 5000 });

// Initialize Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const server = app.listen(5000);
const wss = new WebSocket.WebSocketServer({
    server: server
});


let clients = {};  // Store clients by their usernames
let groups = {};  // Store groups with group name as key and group data as value

// Temporary storing user's username && password
let database_users = [
    {
        username: 'user1',
        password: 'pass1'
    },
    {
        username: 'user2',
        password: 'pass2'
    },
    {
        username: 'user3',
        password: 'pass3'
    }
];

// Helper function to generate a unique 8-digit username
function generateUsername() {
    let username;
    do {
        username = Math.floor(Math.random() * 100000000).toString().padStart(8, '0');
    } while (clients[username]);
    return username;
}

// Function to check if username and password given correctly in the database
async function checkUserPass(username, password) {
    // Debug without database
    /*
    for (let i = 0; i < database_users.length; i++) {
        if (database_users[i].username === username) {
            if (bcrypt.compareSync(database_users[i].password, password)) {
                return true;
            } else {
                return false;
            }
        }
    };

    return false
    */

    // Debug with database
    let result = (await db.promise().query('SELECT * FROM users WHERE username = ?', [username]))[0];
    if (result.length > 0) {
        if (bcrypt.compareSync(password, result[0].password)) {
            return true
        } else {
            return false;
        }
    } else {
        return false;
    }
}

// Function to check if user existed in database
async function checkUserExisted(username) {
    // Debug without using database
    /*
    for (let i = 0; i < database_users.length; i++) {
        if (database_users[i].username === username) {
            return true
        }
    }

    return false;
    */

    // Debug with database
    let result = (await db.promise().query('SELECT * FROM users WHERE username = ?', [username]))[0];
    if (result.length > 0) {
        return true
    } else {
        return false;
    }
}

// Function to add new users to database
async function addNewUsers(username, password) {
    // Debug without using database
    /*
    let hashedPassword = await bcrypt.hash(password, 10);
    database_users.push({ username, password: hashedPassword });
    */

    // Debug with database
    let hashedPassword = await bcrypt.hash(password, 10);
    await db.promise().query('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
}

// HTTP login request
app.post('/login', async (req, res) => {
    // Validate If input existed
    if (!(
        req.body.username &&
        req.body.password
    ))
        return res.status(400).json({ success: false, message: "Pleases complete the login form!" });

    // Find user in database
    let username = req.body.username;
    let password = req.body.password;
    let login_result = await checkUserPass(username, password);

    // Return login result
    if (login_result) {
        if (clients[username]) {
            return res.status(500).json({ success: false, message: 'Log in fails!' });
        }

        clients[username] = "can_access";
        return res.status(201).json({ success: true, message: 'Log in successful!' });
    } else {
        return res.status(500).json({ success: false, message: 'Log in fails!' });
    }
});

// HTTP register request
app.post('/register', async (req, res) => {
    // Validate If input existed
    if (!(
        req.body.username &&
        req.body.password
    ))
        return res.status(400).json({ success: false, message: "Pleases complete the login form!" });

    // Find user in database
    let username = req.body.username;
    let password = req.body.password;
    let user_existed = await checkUserExisted(username);

    // Return register result
    if (user_existed) {
        return res.status(500).json({ success: false, message: 'Register fails!' });
    } else {
        await addNewUsers(username, password);
        return res.status(201).json({ success: true, message: 'Register successful!' });
    }
});

wss.on('connection', (ws, req) => {
    /*
    let username = generateUsername();  // Assign a unique 8-digit username to the client
    clients[username] = { ws, groups: [] };  // Store client with the generated username and group memberships

    // Notify the client of their unique username
    ws.send(`Welcome! Your unique username is ${username}. You can now send direct messages using /dm <username> <message>.`);
    */


    let username = (url.parse(req.url, true).query).username; // Get username from request link
    if (username && clients[username] === "can_access") {
        clients[username] = ws;  // Store client with the generated username
    } else {
        ws.close(1008, 'Username is required to connect.');
        return;
    }

    // Notify the client with their username
    ws.send(`Welcome, ${username}! You can now send direct messages using /dm <username> <message>.`);


    // Handle incoming messages
    ws.on('message', async (message) => {
        message = message.toString();  // Ensure message is a string

        console.log(`Received message from ${username}: ${message}`);

        // Handle /dm command for direct messaging
        if (message.startsWith('/dm')) {
            const parts = message.split(' ');
            const targetUser = parts[1]; // The recipient's username
            const dmMessage = parts.slice(2).join(' '); // The message content

            if (clients[targetUser]) {
                // Send the message to the specific client
                clients[targetUser].send(`${username}: ${dmMessage}`);


                await db.promise().query(
                    'INSERT INTO chat_history (sender_id, receiver_id, message) SELECT (SELECT id FROM users WHERE username = ?), (SELECT id FROM users WHERE username = ?), ?',
                    [username, targetUser, dmMessage]);

                ws.send(`You sent a DM to ${targetUser}: ${dmMessage}`);
            } else {
                ws.send(`User ${targetUser} is not connected.`);
            }
        }

        // Handle /create-group to create a new group
        else if (message.startsWith('/create-group')) {
            const groupName = message.split(' ')[1];

            // Debug without database
            /*
            if (!groups[groupName]) {
                groups[groupName] = {
                    admin: username,
                    members: [username],
                    messages: []
                };
                ws.send(`Group '${groupName}' created. You are the admin.`);
            } else {
                ws.send(`Group '${groupName}' already exists.`);
            }
            */

            // Debug with database
            let result = (await db.promise().query('SELECT * FROM chat_groups WHERE group_name = ?', [groupName]))[0];
            if (result.length > 0) {
                ws.send(`Group '${groupName}' already exists.`);
            } else {

                await db.promise().query(
                    'INSERT INTO chat_groups (admin_user_id, group_name) SELECT (SELECT id FROM users WHERE username = ?), ?',
                    [username, groupName]);
                await db.promise().query('INSERT INTO group_members (member_user_id, group_id) SELECT (SELECT id FROM users WHERE username = ?), (SELECT id FROM chat_groups WHERE group_name = ?)', [username, groupName]);

                ws.send(`Group '${groupName}' created. You are the admin.`);
            }
        }

        // Handle /join to request joining a group
        else if (message.startsWith('/join')) {
            const groupName = message.split(' ')[1];

            // Debug without database
            /*
            if (groups[groupName]) {
                // Notify the admin of the request to join
                const admin = groups[groupName].admin;
                clients[admin].ws.send(`${username} wants to join the group '${groupName}'. Use /add-member <username> to add them.`);
                ws.send(`Your request to join '${groupName}' has been sent to the admin.`);
            } else {
                ws.send(`Group '${groupName}' does not exist.`);
            }
            */

            // Debug with database
            let result = (await db.promise().query('SELECT * FROM chat_groups WHERE group_name = ?', [groupName]))[0];
            if (result.length > 0) {
                let admin = (await db.promise().query('SELECT username FROM users WHERE id = ?', result[0].admin_user_id))[0][0].username;
                clients[admin].send(`${username} wants to join the group '${groupName}'. Use /add-member <username> to add them.`);
                ws.send(`Your request to join '${groupName}' has been sent to the admin.`);
            } else {
                ws.send(`Group '${groupName}' does not exist.`);
            }

        }

        // Handle /add-member to add a user to a group (only admin)
        else if (message.startsWith('/add-member')) {
            const groupName = message.split(' ')[1];
            const newUser = message.split(' ')[2];

            // Debug without database
            /*
            if (groups[groupName] && groups[groupName].admin === username) {
                if (clients[newUser]) {
                    groups[groupName].members.push(newUser);
                    clients[newUser].ws.send(`${username} has added you to the group '${groupName}'.`);
                    ws.send(`You have added ${newUser} to '${groupName}'.`);
                } else {
                    ws.send(`User ${newUser} is not connected.`);
                }
            } else {
                ws.send('You do not have permission to add members to this group.');
            }
            */

            // Debug with database
            let result = (await db.promise().query(`SELECT c.id
                                                    FROM chat_groups c
                                                    INNER JOIN users u
                                                    ON c.admin_user_id = u.id
                                                    WHERE c.group_name = ? AND u.username = ?`, [groupName, username]))[0];

            if (result.length > 0) {
                if (clients[newUser]) {
                    let group_id = result[0].id;
                    await db.promise().query('INSERT INTO group_members (member_user_id, group_id) SELECT (SELECT id FROM users WHERE username = ?), ?', [newUser, group_id]);
                    clients[newUser].send(`${username} has added you to the group '${groupName}'.`);
                    ws.send(`You have added ${newUser} to '${groupName}'.`);
                } else {
                    ws.send(`User ${newUser} is not connected.`);
                }
            } else {
                ws.send('You do not have permission to add members to this group.');
            }
        }


        // Handle /remove-member to remove a user from a group (only admin)
        else if (message.startsWith('/remove-member')) {
            const groupName = message.split(' ')[1];
            const userToRemove = message.split(' ')[2];

            // Debug without database
            /*
            if (groups[groupName] && groups[groupName].admin === username) {
                const index = groups[groupName].members.indexOf(userToRemove);
                if (index !== -1) {
                    groups[groupName].members.splice(index, 1);
                    clients[userToRemove].ws.send(`You have been removed from the group '${groupName}'.`);
                    ws.send(`You have removed ${userToRemove} from '${groupName}'.`);
                } else {
                    ws.send(`${userToRemove} is not a member of the group.`);
                }
            } else {
                ws.send('You do not have permission to remove members from this group.');
            }
            */

            // Debug with database
            let result = (await db.promise().query(`SELECT c.id
                FROM chat_groups c
                INNER JOIN users u
                ON c.admin_user_id = u.id
                WHERE c.group_name = ? AND u.username = ?`, [groupName, username]))[0];

            if (result.length > 0) {

                let search_result = (await db.promise().query(`SELECT c.id as group_id, u.id as user_id, u.username as delete_username
                                                                FROM chat_groups c
                                                                INNER JOIN group_members m
                                                                ON c.id = m.group_id
                                                                INNER JOIN users u
                                                                ON m.member_user_id = u.id
                                                                WHERE u.username = ? AND c.group_name = ?`, [userToRemove, groupName]))[0];
                if (search_result.length > 0) {
                    if (search_result[0].delete_username === username) {
                        return ws.send(`You can't remove admin of this group`);
                    }

                    await db.promise().query('DELETE FROM group_members WHERE group_id = ? AND member_user_id = ?', [search_result[0].group_id, search_result[0].user_id]);
                    clients[userToRemove] && clients[userToRemove].send(`You have been removed from the group '${groupName}'.`);
                    ws.send(`You have removed ${userToRemove} from '${groupName}'.`);
                } else {
                    ws.send(`${userToRemove} is not a member of the group.`);
                }
            } else {
                ws.send('You do not have permission to add members to this group.');
            }
        }

        // Handle group messages, only send to group members
        else if (message.startsWith('/group-message')) {
            const parts = message.split(' ');
            const groupName = parts[1];
            const groupMessage = parts.slice(2).join(' ');

            // Debug without database
            /*
            if (groups[groupName] && groups[groupName].members.includes(username)) {
                groups[groupName].messages.push({ sender: username, message: groupMessage });
                groups[groupName].members.forEach(member => {
                    clients[member].ws.send(`[Group ${groupName}] ${username}: ${groupMessage}`);
                });
            } else {
                ws.send(`You are not a member of the group '${groupName}'.`);
            }
            */

            // Debug with database
            let search_result = (await db.promise().query(`SELECT c.id as group_id, u.id as user_id
                FROM chat_groups c
                INNER JOIN group_members m
                ON c.id = m.group_id
                INNER JOIN users u
                ON m.member_user_id = u.id
                WHERE u.username = ? AND c.group_name = ?`, [username, groupName]))[0];
            if (search_result.length > 0) {
                await db.promise().query('INSERT INTO group_messages (group_id, message, sender_user_id) VALUES(?, ?, ?)', [search_result[0].group_id, groupMessage, search_result[0].user_id]);
                let users_to_send = (await db.promise().query(`SELECT u.username
                                                                FROM users u
                                                                INNER JOIN group_members g
                                                                ON u.id = g.member_user_id
                                                                WHERE g.group_id = ?`, [search_result[0].group_id]))[0];


                for (let i = 0; i < users_to_send.length; i++) {
                    clients[users_to_send[i].username] && clients[users_to_send[i].username].send(`[Group ${groupName}] ${username}: ${groupMessage}`);
                }
            } else {
                ws.send(`${userToRemove} is not a member of the group.`);
            }
        }

        else {
            ws.send('Unknown command.');
        }
    });

    ws.on('close', async () => {
        delete clients[username];  // Remove client when they disconnect
        console.log(`User ${username} disconnected.`);
        // Also remove client from any group they were part of

        // Debug without database
        /*
        for (let groupName in groups) {
            const group = groups[groupName];
            const index = group.members.indexOf(username);
            if (index !== -1) {
                group.members.splice(index, 1);
            }
        }
        */

        // Debug with database
        await db.promise().query(`DELETE FROM group_members
                                    WHERE member_user_id = (
	                                SELECT id FROM users WHERE username = ?
        )`, [username]);

    });
});

console.log('Server started on ws://localhost:5000');
