<?php

declare(strict_types=1);
session_start();

const DB_HOST = 'localhost';
const DB_NAME = 'mi_base';
const DB_USER = 'root';
const DB_PASS = '';
const APP_NOMBRE = 'Mi Sistema';
const PAGINA_INICIO = 'login.php';   // a dónde ir después del login
const MAX_INTENTOS = 5;              // intentos antes de bloquear
const BLOQUEO_SEG  = 300;            // 5 minutos

function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}
function e(?string $v): string {
    return htmlspecialchars($v ?? '', ENT_QUOTES, 'UTF-8');
}
function csrf_token(): string {
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

// Si ya inició sesión, mandarlo al inicio
if (isset($_SESSION['usuario_id'])) {
    header('Location: ' . PAGINA_INICIO);
    exit;
}

$error = null;
$usuario = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario  = trim($_POST['usuario'] ?? '');
    $password = $_POST['password'] ?? '';

    $intentos = $_SESSION['intentos'] ?? 0;
    $bloqueo  = $_SESSION['bloqueo_hasta'] ?? 0;

    if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
        $error = 'Sesión expirada. Recarga la página.';
    } elseif ($bloqueo > time()) {
        $error = 'Demasiados intentos. Espera ' . ceil(($bloqueo - time()) / 60) . ' min.';
    } elseif ($usuario === '' || $password === '') {
        $error = 'Ingresa usuario y contraseña.';
    } else {
        try {
            $stmt = db()->prepare(
                'SELECT id, usuario, nombre, password_hash, rol
                   FROM usuarios
                  WHERE usuario = :u AND activo = 1
                  LIMIT 1'
            );
            $stmt->execute([':u' => $usuario]);
            $u = $stmt->fetch();

            if ($u && password_verify($password, $u['password_hash'])) {
                session_regenerate_id(true);           // evita fijación de sesión
                $_SESSION['usuario_id'] = (int)$u['id'];
                $_SESSION['usuario']    = $u['usuario'];
                $_SESSION['nombre']     = $u['nombre'];
                $_SESSION['rol']        = $u['rol'];
                unset($_SESSION['intentos'], $_SESSION['bloqueo_hasta']);

                db()->prepare('UPDATE usuarios SET ultimo_acceso = NOW() WHERE id = :id')
                    ->execute([':id' => $u['id']]);

                header('Location: ' . PAGINA_INICIO);
                exit;
            }

            $intentos++;
            $_SESSION['intentos'] = $intentos;
            if ($intentos >= MAX_INTENTOS) {
                $_SESSION['bloqueo_hasta'] = time() + BLOQUEO_SEG;
                $_SESSION['intentos'] = 0;
            }
            $error = 'Usuario o contraseña incorrectos.';
        } catch (PDOException $ex) {
            $error = 'Error de conexión con la base de datos.';
        }
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Iniciar sesión · <?= e(APP_NOMBRE) ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
  <style>
    body { min-height: 100vh; background: linear-gradient(135deg, #1e293b, #334155); }
    .login-card { max-width: 400px; width: 100%; }
  </style>
</head>
<body class="d-flex align-items-center justify-content-center p-3">

<div class="card shadow-lg border-0 login-card">
  <div class="card-body p-4 p-md-5">
    <div class="text-center mb-4">
      <i class="bi bi-shield-lock text-primary" style="font-size: 3rem;"></i>
      <h1 class="h4 mt-2 mb-0"><?= e(APP_NOMBRE) ?></h1>
      <p class="text-muted small">Ingresa tus credenciales</p>
    </div>

    <?php if ($error): ?>
      <div class="alert alert-danger py-2 small">
        <i class="bi bi-exclamation-triangle"></i> <?= e($error) ?>
      </div>
    <?php endif; ?>

    <?php if (isset($_GET['salio'])): ?>
      <div class="alert alert-success py-2 small">Sesión cerrada correctamente.</div>
    <?php endif; ?>

    <form method="post" novalidate>
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

      <div class="form-floating mb-3">
        <input type="text" class="form-control" id="usuario" name="usuario"
               placeholder="Usuario" value="<?= e($usuario) ?>" autocomplete="username" required autofocus>
        <label for="usuario"><i class="bi bi-person"></i> Usuario</label>
      </div>

      <div class="input-group mb-3">
        <div class="form-floating">
          <input type="password" class="form-control" id="password" name="password"
                 placeholder="Contraseña" autocomplete="current-password" required>
          <label for="password"><i class="bi bi-key"></i> Contraseña</label>
        </div>
        <button class="btn btn-outline-secondary" type="button" id="verPass" title="Mostrar contraseña">
          <i class="bi bi-eye"></i>
        </button>
      </div>

      <button class="btn btn-primary w-100 py-2" type="submit">
        <i class="bi bi-box-arrow-in-right"></i> Entrar
      </button>
    </form>
  </div>
  <div class="card-footer text-center text-muted small bg-white">
    &copy; <?= date('Y') ?> <?= e(APP_NOMBRE) ?>
  </div>
</div>

<script>
  document.getElementById('verPass').addEventListener('click', function () {
    const p = document.getElementById('password');
    const visible = p.type === 'text';
    p.type = visible ? 'password' : 'text';
    this.innerHTML = visible ? '<i class="bi bi-eye"></i>' : '<i class="bi bi-eye-slash"></i>';
  });
</script>
</body>
</html>