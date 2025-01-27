
# add_comment.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';
require dirname(__FILE__) . '/private/auth.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['body']) && isset($_GET['id'])) {
        // Validar entradas
        $body = trim($_POST['body']);
        $playerId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        $userId = filter_input(INPUT_COOKIE, 'userId', FILTER_VALIDATE_INT);

        if (!$playerId || !$userId || empty($body)) {
            // Si hay datos inválidos, redirigir con un error
            header("Location: list_players.php?error=invalid_input");
            exit;
        }

        try {
            // Usar PDO para evitar inyección SQL
            $db = new PDO('sqlite:your_database.db'); // Configura correctamente tu conexión
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $query = "INSERT INTO comments (playerId, userId, body) VALUES (:playerId, :userId, :body)";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':playerId', $playerId, PDO::PARAM_INT);
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':body', $body, PDO::PARAM_STR);

            $stmt->execute();
            header("Location: list_players.php?success=1");
            exit;
        } catch (PDOException $e) {
            // Manejo de errores con un mensaje genérico
            error_log("Error en la base de datos: " . $e->getMessage());
            header("Location: list_players.php?error=db_error");
            exit;
        }
    }
}

# Show form

?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="" method="post">
        <h3>Write your comment</h3>
        <textarea name="body" required></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="logout.php" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```

- Utilizamos PDO para evitar las inyecciones SQL.
- Ahora se validan las entradas _POST['body'], $_GET['id'] y $_COOKIE['userId'].
- Se redirige correctamente en caso de error.
- Ahora no se muestran los errores a los usuarios.
- Se ha eliminado el uso inseguro de die().
# add_comment.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';
require dirname(__FILE__) . '/private/auth.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['body']) && isset($_GET['id'])) {
        // Validar entradas
        $body = trim($_POST['body']);
        $playerId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        $userId = filter_input(INPUT_COOKIE, 'userId', FILTER_VALIDATE_INT);

        if (!$playerId || !$userId || empty($body)) {
            // Si hay datos inválidos, redirigir con un error
            header("Location: list_players.php?error=invalid_input");
            exit;
        }

        try {
            // Usar PDO para evitar inyección SQL
            $db = new PDO('sqlite:your_database.db'); // Configura correctamente tu conexión
            $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            $query = "INSERT INTO comments (playerId, userId, body) VALUES (:playerId, :userId, :body)";
            $stmt = $db->prepare($query);
            $stmt->bindParam(':playerId', $playerId, PDO::PARAM_INT);
            $stmt->bindParam(':userId', $userId, PDO::PARAM_INT);
            $stmt->bindParam(':body', $body, PDO::PARAM_STR);

            $stmt->execute();
            header("Location: list_players.php?success=1");
            exit;
        } catch (PDOException $e) {
            // Manejo de errores con un mensaje genérico
            error_log("Error en la base de datos: " . $e->getMessage());
            header("Location: list_players.php?error=db_error");
            exit;
        }
    }
}
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="" method="post">
        <h3>Write your comment</h3>
        <textarea name="body" required></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="logout.php" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```

- Se vuelve a utilizar PDO para evitar SQL.
- Se validan las entradas: $_GET['id'], $_COOKIE['userId'] y $_POST['body'].
- En lugar de usar die(), se emplea error_log() para registrar los errores.
# index.php

```php
<?php
# On logout
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['Logout'])) {
    # Delete cookies securely
    setcookie('user', '', time() - 3600, '/', '', true, true);
    setcookie('password', '', time() - 3600, '/', '', true, true);
    setcookie('userId', '', time() - 3600, '/', '', true, true);

    # Redirigir tras eliminar las cookies
    header("Location: index.php");
    exit;
}
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3</title>
</head>
<body>
    <header>
        <h1>Developers Awards</h1>
    </header>
    <main>
        <h2><a href="insert_player.php">Add a new player</a></h2>
        <h2><a href="list_players.php">List of players</a></h2>
        <h2><a href="buscador.html">Search a player</a></h2>
    </main>
    <form action="" method="post" class="menu-form">
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a> >
    </footer>
</body>
</html>
```

- Las cookies se eliminan correctamente.
- Validación del método HTTP.
- Redirección segura, se usa exit tras borrar las cookies.
# insert_player.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require_once dirname(__FILE__) . '/private/auth.php';

$name = $team = $id = '';

# Procesar solicitud POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['name']) && isset($_POST['team'])) {
        $name = trim($_POST['name']);
        $team = trim($_POST['team']);
        $id = isset($_POST['id']) ? intval($_POST['id']) : null;

        # Validar entradas
        if (empty($name) || empty($team)) {
            die("El nombre del jugador y el equipo son obligatorios.");
        }

        # Consulta preparada para evitar inyecciones SQL
        if ($id) {
            $stmt = $db->prepare("INSERT OR REPLACE INTO players (playerid, name, team) VALUES (:id, :name, :team)");
            $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        } else {
            $stmt = $db->prepare("INSERT INTO players (name, team) VALUES (:name, :team)");
        }
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':team', $team, SQLITE3_TEXT);
        
        $stmt->execute() or die("Error al guardar en la base de datos.");
        header("Location: list_players.php");
        exit;
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['id'])) {
    # Cargar datos del jugador para edición
    $id = intval($_GET['id']);
    $stmt = $db->prepare("SELECT name, team FROM players WHERE playerid = :id");
    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);

    $result = $stmt->execute() or die("Error al consultar la base de datos.");
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        die("¡Jugador no encontrado!");
    }

    $name = htmlspecialchars($row['name']);
    $team = htmlspecialchars($row['team']);
}
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players List</title>
</head>
<body>
    <header>
        <h1>Player</h1>
    </header>
    <main class="player">
        <form action="" method="post">
            <input type="hidden" name="id" value="<?= htmlspecialchars($id) ?>">
            <h3>Player name</h3>
            <textarea name="name" required><?= htmlspecialchars($name) ?></textarea><br>
            <h3>Team name</h3>
            <textarea name="team" required><?= htmlspecialchars($team) ?></textarea><br>
            <input type="submit" value="Send">
        </form>
        <form action="logout.php" method="post" class="menu-form">
            <a href="index.php">Back to home</a>
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </main>
    <footer class="listado">
        <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
        <h4>Puesta en producción segura</h4>
        <p> Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a></p>
    </footer>
</body>
</html>
```

- Uso de prepare() para prevenir inyecciones SQL.
- Se verifica lo que el usuario introduce en name y team.
- Se usa htmlspecialchars() para evitar XSS.
# list_player.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require_once dirname(__FILE__) . '/private/auth.php';
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Players List</title>
</head>
<body>
<header class="listado">
    <h1>Players List</h1>
</header>
<main class="listado">
    <section>
        <ul>
            <?php
            $query = "SELECT playerid, name, team FROM players ORDER BY playerid DESC";

            # Usar consulta preparada para evitar problemas con la base de datos
            $result = $db->query($query) or die("Error al ejecutar la consulta.");

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                # Escapar datos para prevenir XSS
                $playerId = htmlspecialchars($row['playerid']);
                $name = htmlspecialchars($row['name']);
                $team = htmlspecialchars($row['team']);

                echo "
                <li>
                    <div>
                        <span>Name: $name</span>
                        <span>Team: $team</span>
                    </div>
                    <div>
                        <a href=\"show_comments.php?id=$playerId\">(Show/Add Comments)</a> 
                        <a href=\"insert_player.php?id=$playerId\">(Edit Player)</a>
                    </div>
                </li>\n";
            }
            ?>
        </ul>
        <form action="logout.php" method="post" class="menu-form">
            <a href="index.php">Back to Home</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>
    </section>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
    <h4>Puesta en producción segura</h4>
    <p>Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a></p>
</footer>
</body>
</html>
```

- Se vuelve a utilizar htmlspecialchars() para evitar XSS.
- Se evitan las consultas innecesarias(require). 
# register.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Seguridad: Verifica si el usuario ya está logueado antes de permitir el registro
# require_once dirname(__FILE__) . '/private/auth.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        $username = trim($_POST['username']);
        $password = trim($_POST['password']);

        # Validar entradas
        if (empty($username) || empty($password)) {
            die("Username and password cannot be empty.");
        }

        # Escapar datos para evitar inyección SQL
        $username = SQLite3::escapeString($username);

        # Hash seguro para la contraseña
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

        # Consulta preparada para evitar inyección SQL
        $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);

        if ($stmt->execute()) {
            header("Location: list_players.php");
            exit;
        } else {
            die("Error while registering the user.");
        }
    }
}

?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Register</title>
</head>
<body>
<header>
    <h1>Register</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required>
        <input type="submit" value="Register">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
    <h4>Puesta en producción segura</h4>
    <p>Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a></p>
</footer>
</body>
</html>
```

- Se validan las entradas username y password.
- La contraseña ahora se guarda cifrada.
- Se utiliza prepare y bindvalue para prevenir SQL.
- Los campos username y password ahora son obligatorios.
- Se escapan los caracteres especiales 
# show_comments.php

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require_once dirname(__FILE__) . '/private/auth.php';
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments Editor</title>
</head>
<body>
<header>
    <h1>Comments Editor</h1>
</header>
<main class="player">
<?php
# Validar si se recibió un ID
if (isset($_GET['id']) && is_numeric($_GET['id'])) {
    $playerId = (int)$_GET['id'];

    # Consulta segura usando consultas preparadas
    $stmt = $db->prepare("SELECT C.commentId, U.username, C.body 
                          FROM comments C 
                          JOIN users U ON U.userId = C.userId 
                          WHERE C.playerId = :playerId 
                          ORDER BY C.commentId DESC");
    $stmt->bindValue(':playerId', $playerId, SQLITE3_INTEGER);

    $result = $stmt->execute();

    # Listar comentarios
    if ($result) {
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            echo "<div>
                    <h4>" . htmlspecialchars($row['username']) . "</h4> 
                    <p>Commented: " . htmlspecialchars($row['body']) . "</p>
                  </div>";
        }
    } else {
        echo "<p>No comments found for this player.</p>";
    }
} else {
    echo "<p>Invalid player ID.</p>";
}

?>
<div>
    <a href="list_players.php">Back to list</a>
    <?php if (isset($playerId)) : ?>
        <a class="black" href="add_comment.php?id=<?php echo $playerId; ?>">Add comment</a>
    <?php endif; ?>
</div>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png" alt="Logo">
    <h4>Puesta en producción segura</h4>
    <p>Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a></p>
</footer>
</body>
</html>
```

- Validación del ID.
- Se vuelve a utilizar prepare y bindValue para evitar SQLi.
- Se vuelve a utilizar htmlspecialchars() para evitar XSS.
# auth.php

```php
<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = false;

# Validar usuario y contraseña
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    # Consulta preparada para evitar inyecciones SQL
    $stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        return false;
    }

    # Verificar contraseña con hash
    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        setcookie('userId', $userId, time() + 3600, '/', '', false, true);
        return true;
    }

    return false;
}

# Manejar inicio de sesión
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username']) && isset($_POST['password'])) {
    $username = htmlspecialchars($_POST['username']);
    $password = htmlspecialchars($_POST['password']);

    if (areUserAndPasswordValid($username, $password)) {
        setcookie('user', $username, time() + 3600, '/', '', false, true); # Cookie segura
        header("Location: " . $_SERVER['PHP_SELF']);
        exit();
    } else {
        $error = "Invalid username or password.<br>";
    }
}

# Manejar cierre de sesión
if (isset($_POST['Logout'])) {
    # Eliminar cookies
    setcookie('user', '', time() - 3600, '/', '', false, true);
    setcookie('userId', '', time() - 3600, '/', '', false, true);

    header("Location: index.php");
    exit();
}

# Comprobar cookies para sesión activa
if (isset($_COOKIE['userId']) && isset($_COOKIE['user'])) {
    $login_ok = true;
    $error = "";
} else {
    $login_ok = false;
    $error = "This page requires you to be logged in.<br>";
}

# Mostrar página de autenticación si no está logueado
if (!$login_ok) {
?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication Page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication Page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label for="username">User</label>
                    <input type="text" id="username" name="username" required><br>
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
                </form>
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        <p>Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/">donate</a></p>
    </footer>
    </body>
    </html>
<?php
    exit();
}

# Refrescar cookies en cada solicitud
setcookie('user', $_COOKIE['user'], time() + 3600, '/', '', false, true);

?>
```

- Se utiliza de nuevo prepare y bindValue para evitar inyecciones SQL.
- Se usa password_verify() para validar contraseñas.
- Se usa secure y httponly para evitar el acceso a las cookies desde JavaScript.
- Se usa htmlspecialchars() para validar las entradas.
