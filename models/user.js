const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

class User {

  static async register({ username, password, first_name, last_name, phone }) {
    try {
      const hashedPassword = await bcrypt.hash(password, 12);

      const newUser = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at)
         VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
         RETURNING username, password, first_name, last_name, phone`,
        [username, hashedPassword, first_name, last_name, phone]
      );

      return newUser.rows[0];
    } catch (error) {
      console.error('Error occurred during user registration:', error);
      throw error;
    }
  }

  static async authenticate(username, password) {
    try {
      const user = await db.query('SELECT * FROM users WHERE username = $1', [username]);

      if (user.rows.length === 0) {
        return null;
      }

      const storedPassword = user.rows[0].password;

      const passwordMatch = await bcrypt.compare(password, storedPassword);

      if (!passwordMatch) {
        return null;
      }

      const { password: _, ...authenticatedUser } = user.rows[0];
      return authenticatedUser;
    } catch (error) {
      console.error('Error occurred during authentication:', error);
      throw error;
    }
  }

  static async updateLoginTimestamp(username) {
    const result = await db.query(
        `UPDATE users
           SET last_login_at = current_timestamp
           WHERE username = $1
           RETURNING username`,
        [username]);

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
  }

  static async all() {
    try {
      const allUsers = await db.query('SELECT username, first_name, last_name, phone FROM users');
      return allUsers.rows;
    } catch (error) {
      console.error('Error occurred while fetching all users:', error);
      throw error;
    }
  }

  static async get(username) {
    try {
      const user = await db.query(
        `SELECT username, first_name, last_name, phone, join_at, last_login_at
         FROM users
         WHERE username = $1`,
        [username]
      );

      if (user.rows.length === 0) {
        return null;
      }

      // Convert last_login_at and join_at to Date objects
      const { last_login_at, join_at, ...userData } = user.rows[0];
      const formattedUser = {
        ...userData,
        last_login_at: new Date(last_login_at),
        join_at: new Date(join_at),
      };

      return formattedUser;
    } 
    catch (error) {
      console.error('Error occurred while fetching user:', error);
      throw error;
    }
  }

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id, m.to_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at
       FROM messages AS m
       JOIN users AS u ON m.to_username = u.username
       WHERE m.from_username = $1`,
      [username]
    );

    return result.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }

  static async messagesTo(username) {
    const result = await db.query(
        `SELECT m.id,
                m.from_username,
                u.first_name,
                u.last_name,
                u.phone,
                m.body,
                m.sent_at,
                m.read_at
          FROM messages AS m
           JOIN users AS u ON m.from_username = u.username
          WHERE to_username = $1`,
        [username]);

    return result.rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
  }}


module.exports = User;