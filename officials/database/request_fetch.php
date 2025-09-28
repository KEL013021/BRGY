<?php
require_once __DIR__ . '/../vendor/autoload.php';

use setasign\Fpdi\Fpdi;

include('../database/config.php');

if (!isset($_GET['id'])) {
    die("Missing request ID.");
}

$requestId = intval($_GET['id']);

// =====================
// 1. Fetch request
// =====================
$sql = "SELECT r.id, r.resident_id, r.service_id, r.purpose, r.request_date, r.status,
               s.service_name
        FROM requests r
        LEFT JOIN services s ON r.service_id = s.id
        WHERE r.id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $requestId);
$stmt->execute();
$request = $stmt->get_result()->fetch_assoc();

if (!$request) {
    die("Request not found.");
}

// =====================
// 2. Fetch resident info
// =====================
$sqlRes = "SELECT * FROM residents WHERE id = ?";
$stmt = $conn->prepare($sqlRes);
$stmt->bind_param("i", $request['resident_id']);
$stmt->execute();
$resident = $stmt->get_result()->fetch_assoc();

if (!$resident) {
    die("Resident not found.");
}

// =====================
// 3. Prepare values array
// =====================

// Compute age from birth_date
$age = '';
if (!empty($resident['date_of_birth'])) {
    $birthDate = new DateTime($resident['date_of_birth']);
    $today     = new DateTime();
    $age       = $today->diff($birthDate)->y; // years old
}


$values = [
    "{{full_name}}"    => $resident['first_name']." ".$resident['middle_name']." ".$resident['last_name'],
    "{{first_name}}"   => $resident['first_name'],
    "{{middle_name}}"  => $resident['middle_name'],
    "{{last_name}}"    => $resident['last_name'],
    "{{gender}}"       => $resident['gender'],
    "{{age}}"          => $age, // ✅ dito na
    "{{birth_date}}"   => $resident['date_of_birth'],
    "{{birth_place}}"  => trim($resident['pob_city'].", ".$resident['pob_province'].", ".$resident['pob_country']),
    "{{civil_status}}" => $resident['civil_status'],
    "{{nationality}}"  => $resident['nationality'],
    "{{religion}}"     => $resident['religion'],

    "{{address}}"      => $resident['house_number']." ".$resident['barangay'].", ".$resident['city'].", ".$resident['province'],
    "{{house_number}}" => $resident['house_number'],
    "{{barangay}}"     => $resident['barangay'],
    "{{city}}"         => $resident['city'],
    "{{province}}"     => $resident['province'],
    "{{country}}"      => $resident['country'],
    "{{zipcode}}"      => $resident['zipcode'],
    "{{zone_purok}}"   => $resident['zone_purok'],

    "{{residency_date}}"      => $resident['residency_date'],
    "{{years_of_residency}}"  => $resident['years_of_residency'],
    "{{residency_type}}"      => $resident['residency_type'],
    "{{previous_address}}"    => $resident['previous_address'],

    "{{father_name}}"   => $resident['father_name'],
    "{{mother_name}}"   => $resident['mother_name'],
    "{{spouse_name}}"   => $resident['spouse_name'],
    "{{family_members}}" => $resident['number_of_family_members'],
    "{{household_number}}" => $resident['household_number'],
    "{{relationship_to_head}}" => $resident['relationship_to_head'],

    "{{house_position}}" => $resident['house_position'],
    "{{educational_attainment}}" => $resident['educational_attainment'],
    "{{current_school}}" => $resident['current_school'],
    "{{occupation}}" => $resident['occupation'],
    "{{monthly_income}}" => $resident['monthly_income'],

    "{{mobile_number}}"   => $resident['mobile_number'],
    "{{telephone_number}}" => $resident['telephone_number'],
    "{{email}}"           => $resident['email_address'],

    "{{emergency_name}}"   => $resident['emergency_contact_person'],
    "{{emergency_number}}" => $resident['emergency_contact_number'],

    "{{pwd_status}}" => $resident['pwd_status'],
    "{{pwd_id_number}}" => $resident['pwd_id_number'],
    "{{senior_status}}" => $resident['senior_citizen_status'],
    "{{senior_id_number}}" => $resident['senior_id_number'],
    "{{solo_parent_status}}" => $resident['solo_parent_status'],
    "{{is_4ps_member}}" => $resident['is_4ps_member'],
    "{{blood_type}}"    => $resident['blood_type'],
    "{{voter_status}}"  => $resident['voter_status'],

    // From request
    "{{purpose}}"      => $request['purpose'],
    "{{request_date}}" => $request['request_date'],
    "{{status}}"       => $request['status'],
    "{{service_name}}" => $request['service_name'],
];

// =====================
// 4. Fetch barangay officials
// =====================
$sqlOfficials = "SELECT position, resident_id FROM barangay_official WHERE address_id = ?";
$stmt = $conn->prepare($sqlOfficials);
$stmt->bind_param("i", $resident['address_id']);
$stmt->execute();
$resOfficials = $stmt->get_result();

while ($o = $resOfficials->fetch_assoc()) {
    $officialName = ""; 
    
    $sqlRes = "SELECT first_name, middle_name, last_name FROM residents WHERE id=?";
    $stmt2 = $conn->prepare($sqlRes);
    $stmt2->bind_param("i", $o['resident_id']);
    $stmt2->execute();
    $resRes = $stmt2->get_result()->fetch_assoc();

    if ($resRes) {
        $officialName = trim($resRes['first_name']." ".$resRes['middle_name']." ".$resRes['last_name']);
    }

    if (strtolower($o['position']) === "captain") {
        $values["{{barangay_captain}}"] = $officialName;
    }
    if (strtolower($o['position']) === "secretary") {
        $values["{{barangay_secretary}}"] = $officialName;
    }
    if (strtolower($o['position']) === "treasurer") {
        $values["{{barangay_treasurer}}"] = $officialName;
    }
}

// =====================
// 5. Auto date placeholders
// =====================
$values["{{day}}"] = date("d");
$values["{{day_name}}"] = date("l");
$values["{{month}}"] = date("m");
$values["{{month_name}}"] = date("F");
$values["{{year}}"] = date("Y");
$values["{{year_short}}"] = date("y");

// =====================
// 6. Fetch layout JSON
// =====================
$layoutSql = "SELECT pdf_template, pdf_layout_data FROM services WHERE id = ?";
$stmt2 = $conn->prepare($layoutSql);
$stmt2->bind_param("i", $request['service_id']);
$stmt2->execute();
$rowLayout = $stmt2->get_result()->fetch_assoc();

$templateFile = "../pdf_templates/" . ($rowLayout['pdf_template'] ?? "default.pdf");
$layoutData = $rowLayout ? json_decode($rowLayout['pdf_layout_data'], true) : [];

// ✅ Support both old (array) and new (object with fields)
$fields = $layoutData['fields'] ?? $layoutData;
$editorCanvasW = $layoutData['canvasWidth'] ?? 0;
$editorCanvasH = $layoutData['canvasHeight'] ?? 0;

// =====================
// 7. Setup FPDI
// =====================
$pdf = new Fpdi();
$pdf->AddPage();
$pdf->setSourceFile($templateFile);
$tplIdx = $pdf->importPage(1);
$pdf->useTemplate($tplIdx, 0, 0, 210);


// =====================
// 8. Apply layout
// =====================
$editorScale = 1.5;        // same as JS editor
$pxToMm = 25.4 / 96;       // 1 px = 0.264583 mm (96 DPI)

$pageWidthMm  = $pdf->GetPageWidth();
$pageHeightMm = $pdf->GetPageHeight();

// Convert PDF page size to px (para makuha ratio)
$pageWidthPx  = $pageWidthMm / $pxToMm;
$pageHeightPx = $pageHeightMm / $pxToMm;

foreach ($fields as $field) {
    if (!isset($field['text'])) continue;

    $key = trim($field['text']);
    $value = $values[$key] ?? $key;

    // Font
    $fontFamily = $field['fontFamily'] ?? 'Helvetica';
    $allowedFonts = ['Arial', 'Helvetica', 'Times', 'Courier'];
    if (!in_array($fontFamily, $allowedFonts)) $fontFamily = 'Helvetica';

    $fontSize = $field['fontSize'] ?? 12;
    $style = '';
    if (($field['fontWeight'] ?? '') === '700' || ($field['fontWeight'] ?? '') === 'bold') $style .= 'B';
    if (($field['fontStyle'] ?? '') === 'italic') $style .= 'I';
    if (($field['textDecoration'] ?? '') === 'underline') $style .= 'U';

    $pdf->SetFont($fontFamily, $style, $fontSize);

    // Color
    if (!empty($field['color'])) {
        if (preg_match('/rgb\((\d+),\s*(\d+),\s*(\d+)\)/', $field['color'], $m)) {
            $pdf->SetTextColor($m[1], $m[2], $m[3]);
        } elseif (preg_match('/#([0-9a-fA-F]{6})/', $field['color'], $m)) {
            $hex = $m[1];
            $r = hexdec(substr($hex,0,2));
            $g = hexdec(substr($hex,2,2));
            $b = hexdec(substr($hex,4,2));
            $pdf->SetTextColor($r,$g,$b);
        } else {
            $pdf->SetTextColor(0,0,0);
        }
    } else {
        $pdf->SetTextColor(0,0,0);
    }

   
// Extra fine-tune adjustments (px) – pwede mong palitan
$adjustXpx = 75;   // positive = move right, negative = move left
$adjustYpx = -30; // positive = move down, negative = move up

// Compute dynamic offset between editor canvas vs actual PDF size
$offsetXpx = $editorCanvasW && $pageWidthPx ? max(0, ($editorCanvasW - $pageWidthPx) / 2) : 0;
$offsetYpx = $editorCanvasH && $pageHeightPx ? max(0, ($editorCanvasH - $pageHeightPx) / 2) : 0;

$realXpx = $field['x'] - $offsetXpx + $adjustXpx;
$realYpx = $field['y'] - $offsetYpx + $adjustYpx;
$realWpx = $field['width'];

$scaleX = $editorCanvasW ? $pageWidthPx / $editorCanvasW : 1;
$scaleY = $editorCanvasH ? $pageHeightPx / $editorCanvasH : 1;

$x = $realXpx * $scaleX * $pxToMm;
$y = $realYpx * $scaleY * $pxToMm;
$w = $realWpx * $scaleX * $pxToMm;


    $align = strtoupper($field['textAlign'] ?? 'L');

  $lineHeight = $fontSize * 0.35;
$textWidth  = $pdf->GetStringWidth($value);

// Lagi sa gitna ng box
$finalX = $x + ($w - $textWidth) / 2;
$finalY = $y;

$pdf->SetXY($finalX, $finalY);
$pdf->Cell($textWidth, $lineHeight, $value, 0, 0, 'C');


}


// =====================
// 9. Output
// =====================
header("Content-Type: application/pdf");
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");

$pdf->Output("I", "Request_$requestId.pdf");
exit;
