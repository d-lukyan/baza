const escapeHTML = (str) => {
  const symbols = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;'
  }
  return str.replace(/[&<>"'/]/g, (s) => symbols[s]);
}

const validation = {

  isValidUsername: (username) => {
    if (typeof username !== 'string') return { valid: false, error: 'Invalid type username!' };
    const value = username.trim();
    if (value.length < 3 || value.length > 64) {
      return { valid: false, error: 'Username short or long!' }
    }
    const isValid = /^\w{3,64}$/.test(value);
    if (!isValid) return { valid: false, error: 'Invalid format!' };
    return { valid: true, value };
  },

  isValidEmail: (email) => {
    if (typeof email !== 'string') return { valid: false, error: "Invalid type email!" };
    const value = email.trim().toLowerCase();
    if (value.length < 1 || value.length > 137) {
      return { valid: false, error: "Email empty or long!" }
    }
    const isValid =/^[a-zA-Z0-9._]{3,128}@baza\.xyz$/.test(value);
    if (!isValid) return { valid: false, error: "Invalid format! Must be prefix@baza.xyz" };
    return { valid: true, value }
  },

  isValidPassword: (password) => {
    if (typeof password !== 'string') return { valid: false, error: 'Invalid type password!' };
    const value = password;
    if (value.length < 8 || value.length > 128) {
      return { valid: false, error: "Password short or long!" };
    }
    const isValid = [
      /[a-zA-Z]/.test(value),
      /[0-9]/.test(value),
      /[\p{P}\p{S}]/u.test(value)
    ].every(Boolean);
    if (!isValid) return {
      valid: false,
      error: "Invalid format! Password must be 8-128 chars and include letters, numbers, and symbols."
    };
    return { valid: true, value }
  },

  isValidMessage: (message) => {
    if (typeof message !== 'string') return { valid: false, error: 'Invalid type message!' };
    const value = message.trim();
    if (value.length < 1 || value.length > 2048) return {
      valid: false, error: 'Message empty or too long!'
    }
    return { valid: true, value: escapeHTML(value) };
  }

};

module.exports = { validation, escapeHTML };
