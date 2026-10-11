<?php

declare(strict_types=1);
session_start();

const DB_HOST = 'localhost';
const DB_NAME = 'mi_base';
const DB_USER = 'root';
const DB_PASS = '';
const APP_NOMBRE = 'Mi Sistema';

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

function e(?string $v): string {               // escapar salida HTML
    return htmlspecialchars($v ?? '', ENT_QUOTES, 'UTF-8');
}
function csrf_token(): string {
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}
function csrf_valido(): bool {
    return hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '');
}
function flash(string $tipo, string $msg): void {
    $_SESSION['flash'] = ['tipo' => $tipo, 'msg' => $msg];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valido()) {
        flash('danger', 'Token inválido. Intenta de nuevo.');
    } else {
        $nombre = trim($_POST['nombre'] ?? '');
        if ($nombre === '') {
            flash('warning', 'El nombre es obligatorio.');
        } else {
            try {
                $stmt = db()->prepare('INSERT INTO registros (nombre) VALUES (:nombre)');
                $stmt->execute([':nombre' => $nombre]);
                flash('success', 'Registro guardado correctamente.');
            } catch (PDOException $ex) {
                flash('danger', 'Error al guardar: ' . $ex->getMessage());
            }
        }
    }
    header('Location: ' . $_SERVER['PHP_SELF']);   // patrón PRG
    exit;
}

$registros = [];
$error = null;
try {
    $registros = db()->query('SELECT id, nombre FROM registros ORDER BY id DESC')->fetchAll();
} catch (PDOException $ex) {
    $error = $ex->getMessage();
}

$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?= e(APP_NOMBRE) ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
</head>
<body class="bg-light">

<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="#"><i class="bi bi-grid"></i> <?= e(APP_NOMBRE) ?></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#menu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="menu">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item"><a class="nav-link active" href="#">Inicio</a></li>
        <li class="nav-item"><a class="nav-link" href="#">Reportes</a></li>
        <li class="nav-item"><a class="nav-link" href="#">Salir</a></li>
      </ul>
    </div>
  </div>
</nav>

<main class="container py-4">

  <?php if ($flash): ?>
    <div class="alert alert-<?= e($flash['tipo']) ?> alert-dismissible fade show">
      <?= e($flash['msg']) ?>
      <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    </div>
  <?php endif; ?>

  <?php if ($error): ?>
    <div class="alert alert-danger">Error de base de datos: <?= e($error) ?></div>
  <?php endif; ?>

  <div class="row g-4">
    <!-- Formulario -->
    <div class="col-md-4">
      <div class="card shadow-sm">
        <div class="card-header fw-semibold">Nuevo registro</div>
        <div class="card-body">
          <form method="post">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
            <div class="mb-3">
              <label class="form-label" for="nombre">Nombre</label>
              <input type="text" class="form-control" id="nombre" name="nombre" required>
            </div>
            <button class="btn btn-primary w-100"><i class="bi bi-save"></i> Guardar</button>
          </form>
        </div>
      </div>
    </div>

    <!-- Tabla -->
    <div class="col-md-8">
      <div class="card shadow-sm">
        <div class="card-header fw-semibold">Registros (<?= count($registros) ?>)</div>
        <div class="table-responsive">
          <table class="table table-hover table-striped mb-0">
            <thead class="table-dark">
              <tr><th>ID</th><th>Nombre</th></tr>
            </thead>
            <tbody>
              <?php if (!$registros): ?>
                <tr><td colspan="2" class="text-center text-muted">Sin registros</td></tr>
              <?php else: foreach ($registros as $r): ?>
                <tr><td><?= (int)$r['id'] ?></td><td><?= e($r['nombre']) ?></td></tr>
              <?php endforeach; endif; ?>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</main>

<footer class="text-center text-muted small py-3">
  &copy; <?= date('Y') ?> <?= e(APP_NOMBRE) ?>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>