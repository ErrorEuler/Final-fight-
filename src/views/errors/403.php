<?php http_response_code(403); ?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 - Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f8f9fa;
            color: #343a40;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
        }

        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
        }

        h1 {
            color: #dc3545;
            margin-top: 0;
        }

        .btn {
            display: inline-block;
            padding: 8px 16px;
            margin: 10px 5px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
        }

        .btn-primary {
            background: #007bff;
            color: white;
        }

        .btn-secondary {
            border: 1px solid #6c757d;
            color: #6c757d;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>403 - Access Denied</h1>
        <p>You don't have permission to access this page.</p>

        <?php if (isset($message)): ?>
            <p><?php echo htmlspecialchars($message); ?></p>
        <?php endif; ?>

        <div>
            <a href="/dashboard" class="btn btn-primary">Go to Dashboard</a>
            <a href="/logout" class="btn btn-secondary">Logout</a>
        </div>
    </div>
</body>

</html>