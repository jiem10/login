<?php
require_once __DIR__ . '/config.php';

if (session_has_expired()) {
    end_session();
    redirect_to('login.php');
}

if (!isset($_SESSION['user_id'])) {
    redirect_to('login.php');
}

$stmt = $conn->prepare(
    'SELECT id, student_number, full_name, email FROM users WHERE id = ?'
);
$stmt->bind_param('i', $_SESSION['user_id']);
$stmt->execute();
$currentUser = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$currentUser) {
    end_session();
    redirect_to('login.php');
}

$result = $conn->query(
    'SELECT id, student_number, full_name, created_at, queue_status
     FROM users
     ORDER BY created_at ASC, id ASC'
);
$queueUsers = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
$_SESSION['LAST_ACTIVITY'] = time();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Queue Roster - Global Reciprocal Colleges</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="dashboard-page">
    <header class="dashboard-header">
        <div class="dashboard-brand">
            <img src="https://i.imgur.com/u75GA9x.png" alt="Global Reciprocal Colleges logo">
            <div>
                <h1>GRC Student Dashboard</h1>
                <span> <b>Queue Management</b></span>
            </div>
        </div>
        <div class="dashboard-account">
            <div class="dashboard-user">
                <strong><?= escape($currentUser['full_name']) ?></strong>
                <span><?= escape($currentUser['student_number']) ?></span>
            </div>
            <a href="logout.php" class="btn-logout">
                <i class="fa-solid fa-right-from-bracket"></i> Logout
            </a>
        </div>
    </header>

    <main class="dashboard-content">
        <section class="queue-heading">
            <div class="queue-title-icon"><i class="fa-solid fa-bullhorn"></i></div>
            <div>
                <h2>Queue Roster</h2>
                <p><i>View registered students, queue numbers, arrival times, and current status at the GRC counter.</i></p>
            </div>
        </section>

        <section class="queue-card" aria-labelledby="queue-table-title">
            <div class="queue-toolbar">
                <div class="queue-filter-group">
                    <label for="status-filter">Status</label>
                    <select id="status-filter">
                        <option value="all">All statuses</option>
                        <option value="waiting">Waiting</option>
                        <option value="serving">Serving</option>
                        <option value="served">Served</option>
                    </select>
                </div>
                <label class="queue-search" for="queue-search">
                    <span class="sr-only">Search the queue</span>
                    <input type="search" id="queue-search" placeholder="Search by name or student number">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </label>
            </div>

            <div class="queue-table-wrapper">
                <table class="queue-table" id="queue-table">
                    <caption id="queue-table-title" class="sr-only">Registered student queue roster</caption>
                    <thead>
                        <tr>
                            <th>Queue No.</th>
                            <th>Student No.</th>
                            <th>Name</th>
                            <th>Time In</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($queueUsers as $queueIndex => $queueUser): ?>
                            <?php
                            $status = in_array($queueUser['queue_status'], ['waiting', 'serving', 'served'], true)
                                ? $queueUser['queue_status']
                                : 'waiting';
                            $timeIn = date('g:i A', strtotime($queueUser['created_at']));
                            ?>
                            <tr data-queue-row data-status="<?= escape($status) ?>" <?= $queueIndex >= 7 ? 'hidden' : '' ?>>
                                <td class="queue-number"><?= 101 + $queueIndex ?></td>
                                <td class="queue-student-number"><?= escape($queueUser['student_number']) ?></td>
                                <td class="queue-name"><?= escape($queueUser['full_name']) ?></td>
                                <td><?= escape($timeIn) ?></td>
                                <td><span class="queue-status queue-status-<?= escape($status) ?>"><?= escape(strtoupper($status)) ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                        <tr class="queue-empty-row" data-queue-empty <?= $queueUsers ? 'hidden' : '' ?>>
                            <td colspan="5">No students match the selected filters.</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="queue-card-footer">
                <span class="queue-result-summary">
                    Showing <strong data-range-start><?= $queueUsers ? 1 : 0 ?></strong>–<strong data-range-end><?= min(7, count($queueUsers)) ?></strong>
                    of <strong data-filtered-count><?= count($queueUsers) ?></strong> students
                </span>
                <nav class="queue-pagination" data-pagination aria-label="Queue roster pages">
                    <button type="button" class="queue-page-button" data-page-previous aria-label="Previous page">
                        <i class="fa-solid fa-chevron-left"></i><span>Previous</span>
                    </button>
                    <div class="queue-page-numbers" data-page-numbers></div>
                    <button type="button" class="queue-page-button" data-page-next aria-label="Next page">
                        <span>Next</span><i class="fa-solid fa-chevron-right"></i>
                    </button>
                </nav>
            </div>
        </section>
    </main>

<script>
    const statusFilter = document.getElementById('status-filter');
    const queueSearch = document.getElementById('queue-search');
    const queueRows = [...document.querySelectorAll('[data-queue-row]')];
    const emptyRow = document.querySelector('[data-queue-empty]');
    const rangeStart = document.querySelector('[data-range-start]');
    const rangeEnd = document.querySelector('[data-range-end]');
    const filteredCount = document.querySelector('[data-filtered-count]');
    const pagination = document.querySelector('[data-pagination]');
    const pageNumbers = document.querySelector('[data-page-numbers]');
    const previousButton = document.querySelector('[data-page-previous]');
    const nextButton = document.querySelector('[data-page-next]');
    const rowsPerPage = 7;
    let currentPage = 1;

    const getFilteredRows = () => {
        const selectedStatus = statusFilter.value;
        const searchTerm = queueSearch.value.trim().toLowerCase();

        return queueRows.filter((row) => {
            const statusMatches = selectedStatus === 'all' || row.dataset.status === selectedStatus;
            const name = row.querySelector('.queue-name')?.textContent.toLowerCase() ?? '';
            const studentNumber = row.querySelector('.queue-student-number')?.textContent.toLowerCase() ?? '';
            const searchMatches = searchTerm === ''
                || name.includes(searchTerm)
                || studentNumber.includes(searchTerm);
            return statusMatches && searchMatches;
        });
    };

    const renderPageNumbers = (totalPages) => {
        pageNumbers.replaceChildren();

        for (let page = 1; page <= totalPages; page += 1) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'queue-page-button queue-page-number';
            button.textContent = page;
            button.setAttribute('aria-label', `Go to page ${page}`);

            if (page === currentPage) {
                button.classList.add('active');
                button.setAttribute('aria-current', 'page');
            }

            button.addEventListener('click', () => {
                currentPage = page;
                renderQueue();
            });
            pageNumbers.append(button);
        }
    };

    const renderQueue = () => {
        const matchingRows = getFilteredRows();
        const totalPages = Math.max(1, Math.ceil(matchingRows.length / rowsPerPage));
        currentPage = Math.min(currentPage, totalPages);
        const startIndex = (currentPage - 1) * rowsPerPage;
        const endIndex = Math.min(startIndex + rowsPerPage, matchingRows.length);

        queueRows.forEach((row) => {
            row.hidden = true;
        });
        matchingRows.slice(startIndex, endIndex).forEach((row) => {
            row.hidden = false;
        });

        const hasMatches = matchingRows.length > 0;
        emptyRow.hidden = hasMatches;
        rangeStart.textContent = hasMatches ? startIndex + 1 : 0;
        rangeEnd.textContent = hasMatches ? endIndex : 0;
        filteredCount.textContent = matchingRows.length;
        pagination.hidden = !hasMatches;
        previousButton.disabled = currentPage === 1;
        nextButton.disabled = currentPage === totalPages;
        renderPageNumbers(totalPages);
    };

    const resetAndRender = () => {
        currentPage = 1;
        renderQueue();
    };

    previousButton.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage -= 1;
            renderQueue();
        }
    });
    nextButton.addEventListener('click', () => {
        const totalPages = Math.max(1, Math.ceil(getFilteredRows().length / rowsPerPage));
        if (currentPage < totalPages) {
            currentPage += 1;
            renderQueue();
        }
    });
    statusFilter.addEventListener('change', resetAndRender);
    queueSearch.addEventListener('input', resetAndRender);
    renderQueue();
</script>
</body>
</html>
