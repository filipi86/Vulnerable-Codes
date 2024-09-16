// Example of vulnerable Kotlin code with secrets in clear text

val apiKey = "12345-abcde-SECRET-54321"
val dbPassword = "password123"

fun getSecret(): String {
    return apiKey
}

fun connectToDb(): String {
    return "Connecting to database with password: $dbPassword"
}

fun main() {
    println(getSecret())
    println(connectToDb())
}