// Example of vulnerable JavaScript code with secrets in clear text

const apiKey = "12345-abcde-SECRET-54321";
const dbPassword = "password123";

function getSecret() {
    return apiKey;
}

function connectToDb() {
    return `Connecting to database with password: ${dbPassword}`;
}

console.log(getSecret());
console.log(connectToDb());