/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

const { BCRYPT_WORK_FACTOR } = require("../config");


/** User of the site. */

class User {
    constructor(username, password, firstName, lastName, phone) {
      this.username = username;
      this.password = password;
      this.firstName = firstName;
      this.lastName = lastName;
      this.phone = phone;
    }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    try {
      const hashPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const results = await db.query(
        ` INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, password`, [username, hashPassword, first_name, last_name, phone]);

      return results.rows[0];

    } catch (error) {
      return error;
    }
  }


  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    try {
      const results = await db.query(
        `SELECT username, password FROM users WHERE username = $1`, [username]);

      const user = results.rows[0];
      if (user) {
        return await bcrypt.compare(password, user.password);
      }
    } catch (error) {
      return error;
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    try {
      const results = await db.query(
        `UPDATE users SET last_login_at = current_timestamp WHERE username = $1`, [username]);
      if (!results.rows[0]) {
        throw new ExpressError(`User does not exist: ${username}`);
      }
    } catch (error) {
      return error;
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    try {
      const results = await db.query(
        `SELECT username, first_name, last_name, phone FROM users ORDER BY username;`);
      if (!results.rows) {
        throw new ExpressError(`There are zero users found in the DataBase.`);
      }
      return results.rows;
    } catch (error) {
      return error;
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    try {
      const results = await db.query(
        `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1;`, [username]);
      if (!results.rows[0]) {
        throw new ExpressError(`User not found: ${username}`, 404);
      }
      return results.rows[0];
    } catch (error) {
      return error;
    }
   }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    try {
      const results = await db.query(
        `SELECT m.id, m.body, m.sent_at, m.read_at, m.to_username, u.first_name, u.last_name, u.phone 
        FROM messages AS m JOIN users AS u ON m.to_username = u.username
        WHERE m.from_username = $1;`, [username]);
      if (!results.rows[0]) {
        throw new ExpressError(`User not found: ${username}`, 404);
      }

      return results.rows.map((m) => ({
        id: m.id,
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
        to_user: {
          username: m.to_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        }
      }));
    } catch (error) {
      return error;
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    try {
      const results = await db.query(
        `SELECT m.id, m.from_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at
          FROM messages AS m JOIN users AS u ON m.from_username = u.username
          WHERE to_username = $1`, [username]);
      if (!results.rows[0]) {
        throw new ExpressError(`User not found: ${username}`, 404);
      }

      return results.rows.map((m) => ({
        id: m.id,
        body: m.body,
        sent_at: m.sent_at,
        read_at: m.read_at,
        from_user: {
          username: m.from_username,
          first_name: m.first_name,
          last_name: m.last_name,
          phone: m.phone,
        },
      }));
    } catch (error) {
      return error;
    }
  }
}


module.exports = User;