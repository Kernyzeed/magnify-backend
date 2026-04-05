// ============================================================
// MAGNIFY SERVICES – Backend Server (Node.js + Express)
// Created by Falcon Africa
// ============================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');

const app = express();

// ── Security Middleware ──────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/', limiter);

// ── Supabase Client ─────────────────────────────────────────
const supabase = createClient(
  'https://YOURPROJECT.supabase.co',
  'YOUR_SERVICE_ROLE_KEY_HERE'
);

// ── Audit Middleware ─────────────────────────────────────────
const auditLog = async (userId, action, tableName, recordId, oldVal, newVal, req) => {
  await supabase.from('audit_log').insert({
    user_id: userId, action, table_name: tableName,
    record_id: recordId, old_values: oldVal, new_values: newVal,
    ip_address: req.ip, user_agent: req.headers['user-agent']
  });
};

// ── Auth Middleware ──────────────────────────────────────────
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = jwt.verify(token, 'magnify2024secretkey');
  } catch { res.status(401).json({ error: 'Invalid token' }); }
};

const authorize = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  next();
};

// ══════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const { data: user } = await supabase.from('users')
    .select('*').eq('email', email).eq('is_active', true).single();
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, 'magnify2024secretkey', { expiresIn: '12h' });
    return res.status(401).json({ error: 'Invalid credentials' });
  await supabase.from('users').update({ last_login: new Date() }).eq('id', user.id);
  const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, role: user.role, userId: user.id });
const token = jwt.sign({ id: req.user.id, role: req.user.role, email: req.user.email }, 'magnify2024secretkey', { expiresIn: '12h' });

app.post('/api/auth/refresh', authenticate, async (req, res) => {
  const token = jwt.sign({ id: req.user.id, role: req.user.role, email: req.user.email }, process.env.JWT_SECRET, { expiresIn: '12h' });
  res.json({ token });
});

// ══════════════════════════════════════════════════════════════
// STAFF ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/staff', authenticate, async (req, res) => {
  const { home_id, status, search } = req.query;
  let query = supabase.from('staff').select(`*, user:users(email, role), home:homes(name), certifications:staff_certifications(*, cert_type:certification_types(name, validity_months))`);
  if (home_id) query = query.eq('home_id', home_id);
  if (status) query = query.eq('status', status);
  if (search) query = query.or(`first_name.ilike.%${search}%,last_name.ilike.%${search}%`);
  const { data, error } = await query.order('last_name');
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/api/staff', authenticate, authorize('owner', 'admin'), async (req, res) => {
  const { data, error } = await supabase.from('staff').insert(req.body).select().single();
  if (error) return res.status(400).json({ error });
  await auditLog(req.user.id, 'CREATE_STAFF', 'staff', data.id, null, req.body, req);
  res.status(201).json(data);
});

app.put('/api/staff/:id', authenticate, authorize('owner', 'admin', 'supervisor'), async (req, res) => {
  const { data: old } = await supabase.from('staff').select().eq('id', req.params.id).single();
  const { data, error } = await supabase.from('staff').update(req.body).eq('id', req.params.id).select().single();
  if (error) return res.status(400).json({ error });
  await auditLog(req.user.id, 'UPDATE_STAFF', 'staff', data.id, old, req.body, req);
  res.json(data);
});

// Certifications
app.get('/api/staff/:id/certifications', authenticate, async (req, res) => {
  const { data, error } = await supabase.from('staff_certifications')
    .select('*, cert_type:certification_types(*)').eq('staff_id', req.params.id);
  res.json(data || []);
});

app.post('/api/staff/:id/certifications', authenticate, authorize('owner', 'admin', 'supervisor'), async (req, res) => {
  const { data, error } = await supabase.from('staff_certifications')
    .insert({ ...req.body, staff_id: req.params.id }).select().single();
  if (error) return res.status(400).json({ error });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════
// RESIDENTS ROUTES
// ══════════════════════════════════════════════════════════════
app.get('/api/residents', authenticate, async (req, res) => {
  const { home_id } = req.query;
  let query = supabase.from('residents').select(`*, home:homes(name), care_plans(*), medications(*)`).eq('is_active', true);
  if (home_id) query = query.eq('home_id', home_id);
  const { data, error } = await query.order('last_name');
  if (error) return res.status(500).json({ error });
  res.json(data);
});

app.post('/api/residents', authenticate, authorize('owner', 'admin'), async (req, res) => {
  const { data, error } = await supabase.from('residents').insert(req.body).select().single();
  if (error) return res.status(400).json({ error });
  await supabase.from('homes').update({ current_occupancy: supabase.raw('current_occupancy + 1') }).eq('id', req.body.home_id);
  await auditLog(req.user.id, 'CREATE_RESIDENT', 'residents', data.id, null, req.body, req);
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════
// SCHEDULING ENGINE
// ══════════════════════════════════════════════════════════════

/**
 * Michigan AFC Scheduling Rules (R 400.633)
 * - Awake supervisor required when residents are awake
 * - Staff:resident ratio varies by care level
 * - Staff must have valid certifications for assigned tasks
 * - Overnight shifts: awake or sleeping supervisor based on residents' needs
 */
const STAFFING_RULES = {
  LOW:       { day: 1/6, evening: 1/6, overnight: 1/6 }, // 1 staff per 6 residents
  MODERATE:  { day: 1/4, evening: 1/4, overnight: 1/6 },
  HIGH:      { day: 1/2, evening: 1/2, overnight: 1/4 },
  INTENSIVE: { day: 1/1, evening: 1/1, overnight: 1/2 },
};

const SHIFT_TIMES = {
  day:       { start: '07:00', end: '15:00' },
  evening:   { start: '15:00', end: '23:00' },
  overnight: { start: '23:00', end: '07:00' },
};

async function getRequiredStaffCount(homeId, shiftType, date) {
  const { data: residents } = await supabase.from('residents')
    .select('care_level').eq('home_id', homeId).eq('is_active', true);
  if (!residents?.length) return 1;
  // Calculate based on highest care level
  const careLevels = residents.map(r => r.care_level.toUpperCase());
  const ratios = careLevels.map(l => STAFFING_RULES[l]?.[shiftType] || 1/6);
  const maxRatio = Math.max(...ratios);
  return Math.max(1, Math.ceil(residents.length * maxRatio));
}

async function getEligibleStaff(homeId, shiftType, date, requiredCerts = []) {
  // Get staff with valid certifications who are available and not already scheduled
  const { data: staff } = await supabase.from('staff')
    .select(`*, certifications:staff_certifications(cert_type_id, expiry_date, status), availability:staff_availability(day_of_week, shift_type, is_available)`)
    .eq('home_id', homeId).eq('status', 'active');

  const dayOfWeek = new Date(date).getDay();
  return (staff || []).filter(s => {
    // Check availability
    const avail = s.availability?.find(a => a.day_of_week === dayOfWeek && a.shift_type === shiftType);
    if (!avail?.is_available) return false;
    // Check required certifications are valid
    if (requiredCerts.length > 0) {
      const validCerts = new Set(s.certifications?.filter(c => c.status === 'valid').map(c => c.cert_type_id));
      return requiredCerts.every(c => validCerts.has(c));
    }
    return true;
  });
}

// AUTO-GENERATE weekly schedule
app.post('/api/schedules/generate', authenticate, authorize('owner', 'admin', 'supervisor'), async (req, res) => {
  const { home_id, week_start } = req.body;
  const weekStart = new Date(week_start);
  const weekEnd = new Date(weekStart); weekEnd.setDate(weekEnd.getDate() + 6);

  try {
    // Create or get schedule record
    const { data: schedule, error: schedErr } = await supabase.from('schedules').upsert({
      home_id, week_start: weekStart.toISOString().split('T')[0],
      week_end: weekEnd.toISOString().split('T')[0],
      generated_by: req.user.id
    }, { onConflict: 'home_id,week_start' }).select().single();
    if (schedErr) throw schedErr;

    const shifts = [];
    const warnings = [];

    // Generate for each day and shift type
    for (let d = 0; d < 7; d++) {
      const shiftDate = new Date(weekStart);
      shiftDate.setDate(shiftDate.getDate() + d);
      const dateStr = shiftDate.toISOString().split('T')[0];

      for (const shiftType of ['day', 'evening', 'overnight']) {
        const required = await getRequiredStaffCount(home_id, shiftType, dateStr);
        const eligible = await getEligibleStaff(home_id, shiftType, dateStr);

        // Sort by hours worked to ensure fairness
        const sorted = eligible.sort((a, b) => (a.weekly_hours || 0) - (b.weekly_hours || 0));

        for (let i = 0; i < required; i++) {
          const assigned = sorted[i];
          if (!assigned) {
            warnings.push(`⚠ No staff available: ${dateStr} ${shiftType}`);
            // Create open shift
            shifts.push({ schedule_id: schedule.id, home_id, staff_id: null,
              shift_date: dateStr, shift_type: shiftType,
              start_time: SHIFT_TIMES[shiftType].start, end_time: SHIFT_TIMES[shiftType].end,
              status: 'open', is_supervisor_shift: i === 0 });
          } else {
            shifts.push({ schedule_id: schedule.id, home_id, staff_id: assigned.id,
              shift_date: dateStr, shift_type: shiftType,
              start_time: SHIFT_TIMES[shiftType].start, end_time: SHIFT_TIMES[shiftType].end,
              status: 'scheduled', is_supervisor_shift: i === 0 });
          }
        }
      }
    }

    // Delete old shifts for this week and insert new ones
    await supabase.from('shifts').delete().eq('schedule_id', schedule.id);
    const { data: createdShifts, error: shiftErr } = await supabase.from('shifts').insert(shifts).select();
    if (shiftErr) throw shiftErr;

    await auditLog(req.user.id, 'GENERATE_SCHEDULE', 'schedules', schedule.id, null, { week_start }, req);
    res.json({ schedule, shifts: createdShifts, warnings, stats: { total: shifts.length, open: warnings.length } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get schedule for a week
app.get('/api/schedules', authenticate, async (req, res) => {
  const { home_id, week_start } = req.query;
  const { data, error } = await supabase.from('schedules')
    .select(`*, shifts(*, staff:staff(first_name, last_name, job_title))`)
    .eq('home_id', home_id).eq('week_start', week_start).single();
  res.json(data || { shifts: [] });
});

// Assign staff to open shift
app.put('/api/shifts/:id/assign', authenticate, authorize('owner', 'admin', 'supervisor'), async (req, res) => {
  const { staff_id } = req.body;
  const { data: old } = await supabase.from('shifts').select().eq('id', req.params.id).single();
  const { data, error } = await supabase.from('shifts').update({ staff_id, status: 'scheduled' }).eq('id', req.params.id).select().single();
  if (error) return res.status(400).json({ error });
  await auditLog(req.user.id, 'ASSIGN_SHIFT', 'shifts', data.id, old, { staff_id }, req);
  res.json(data);
});

// ══════════════════════════════════════════════════════════════
// TIME & ATTENDANCE
// ══════════════════════════════════════════════════════════════
app.post('/api/timeclock/clockin', authenticate, async (req, res) => {
  const { shift_id, home_id, lat, lng, photo_url } = req.body;
  // Prevent double clock-in
  const { data: existing } = await supabase.from('time_entries')
    .select().eq('staff_id', req.user.staffId).is('clock_out', null).single();
  if (existing) return res.status(400).json({ error: 'Already clocked in' });

  const { data, error } = await supabase.from('time_entries').insert({
    staff_id: req.user.staffId, shift_id, home_id,
    clock_in: new Date().toISOString(),
    clock_in_lat: lat, clock_in_lng: lng, clock_in_photo_url: photo_url
  }).select().single();
  if (error) return res.status(400).json({ error });

  // Update shift status
  if (shift_id) await supabase.from('shifts').update({ status: 'in_progress' }).eq('id', shift_id);
  res.json(data);
});

app.post('/api/timeclock/clockout', authenticate, async (req, res) => {
  const { lat, lng, photo_url, notes } = req.body;
  const { data: entry } = await supabase.from('time_entries')
    .select().eq('staff_id', req.user.staffId).is('clock_out', null).single();
  if (!entry) return res.status(400).json({ error: 'Not clocked in' });

  const clockOut = new Date();
  const hours = (clockOut - new Date(entry.clock_in)) / 3600000;
  const overtime = Math.max(0, hours - 8);

  const { data, error } = await supabase.from('time_entries').update({
    clock_out: clockOut.toISOString(), clock_out_lat: lat, clock_out_lng: lng,
    clock_out_photo_url: photo_url, hours_worked: hours.toFixed(2),
    overtime_hours: overtime.toFixed(2), notes
  }).eq('id', entry.id).select().single();

  if (entry.shift_id) await supabase.from('shifts').update({ status: 'completed' }).eq('id', entry.shift_id);
  res.json(data);
});

app.get('/api/timeclock/live', authenticate, authorize('owner', 'admin', 'supervisor'), async (req, res) => {
  const { home_id } = req.query;
  const { data } = await supabase.from('time_entries')
    .select(`*, staff:staff(first_name, last_name, job_title)`)
    .is('clock_out', null).eq('home_id', home_id);
  res.json(data || []);
});

// ══════════════════════════════════════════════════════════════
// INCIDENTS
// ══════════════════════════════════════════════════════════════
app.post('/api/incidents', authenticate, async (req, res) => {
  const { data, error } = await supabase.from('incidents')
    .insert({ ...req.body, reported_by: req.user.staffId }).select().single();
  if (error) return res.status(400).json({ error });
  // Create alert for admin
  await supabase.from('alerts').insert({
    home_id: req.body.home_id, alert_type: 'incident',
    priority: req.body.severity === 'critical' ? 'critical' : 'high',
    title: `New Incident: ${req.body.incident_type}`,
    message: req.body.description.substring(0, 200),
    related_resident_id: req.body.resident_id
  });
  res.status(201).json(data);
});

// ══════════════════════════════════════════════════════════════
// COMPLIANCE & REPORTING
// ══════════════════════════════════════════════════════════════
app.get('/api/reports/compliance', authenticate, authorize('owner', 'admin', 'auditor'), async (req, res) => {
  const { home_id, period_start, period_end } = req.query;
  const [staffResult, certResult, incidentResult, shiftResult] = await Promise.all([
    supabase.from('staff').select('*').eq('home_id', home_id).eq('status', 'active'),
    supabase.from('v_expiring_certs').select('*'),
    supabase.from('incidents').select('*').eq('home_id', home_id).gte('incident_date', period_start).lte('incident_date', period_end),
    supabase.from('shifts').select('*').eq('home_id', home_id).gte('shift_date', period_start).lte('shift_date', period_end),
  ]);
  const openShifts = shiftResult.data?.filter(s => s.status === 'open') || [];
  const compliance = {
    total_staff: staffResult.data?.length || 0,
    expiring_certs: certResult.data?.length || 0,
    total_incidents: incidentResult.data?.length || 0,
    lara_reportable: incidentResult.data?.filter(i => i.lara_report_required).length || 0,
    open_shifts: openShifts.length,
    coverage_rate: shiftResult.data?.length ? ((shiftResult.data.length - openShifts.length) / shiftResult.data.length * 100).toFixed(1) : 100,
    report_generated: new Date().toISOString()
  };
  res.json(compliance);
});

// Alerts
app.get('/api/alerts', authenticate, async (req, res) => {
  const { data } = await supabase.from('alerts').select('*')
    .eq('is_resolved', false).order('created_at', { ascending: false }).limit(50);
  res.json(data || []);
});

// Dashboard stats
app.get('/api/dashboard', authenticate, async (req, res) => {
  const { home_id } = req.query;
  const today = new Date().toISOString().split('T')[0];
  const [staffing, residents, openShifts, alerts, incidents] = await Promise.all([
    supabase.from('time_entries').select('*, staff:staff(first_name, last_name)').is('clock_out', null).eq('home_id', home_id),
    supabase.from('residents').select('care_level').eq('home_id', home_id).eq('is_active', true),
    supabase.from('shifts').select('*').eq('home_id', home_id).eq('shift_date', today).eq('status', 'open'),
    supabase.from('alerts').select('*').eq('is_resolved', false).order('created_at', { ascending: false }).limit(5),
    supabase.from('incidents').select('*').eq('home_id', home_id).eq('status', 'open')
  ]);
  res.json({
    on_duty: staffing.data?.length || 0,
    resident_count: residents.data?.length || 0,
    open_shifts: openShifts.data?.length || 0,
    unresolved_incidents: incidents.data?.length || 0,
    recent_alerts: alerts.data || [],
    on_duty_staff: staffing.data || []
  });
});

// ══════════════════════════════════════════════════════════════
// CRON JOBS – Automated Compliance Checks
// ══════════════════════════════════════════════════════════════
// Check cert expirations daily at 6 AM
cron.schedule('0 6 * * *', async () => {
  const { data: expiring } = await supabase.from('v_expiring_certs').select('*');
  for (const cert of (expiring || [])) {
    if (cert.days_until_expiry <= 30) {
      await supabase.from('alerts').insert({
        alert_type: 'cert_expiry',
        priority: cert.days_until_expiry <= 7 ? 'critical' : cert.days_until_expiry <= 14 ? 'high' : 'medium',
        title: `Certification Expiring: ${cert.cert_name}`,
        message: `${cert.staff_name}'s ${cert.cert_name} expires in ${cert.days_until_expiry} days.`,
      });
      // Update cert status
      await supabase.from('staff_certifications')
        .update({ status: cert.days_until_expiry <= 0 ? 'expired' : 'expiring_soon' })
        .lt('expiry_date', new Date(Date.now() + 30 * 86400000).toISOString());
    }
  }
  console.log(`[CRON] Cert check: ${expiring?.length || 0} expiring`);
});

// Check for uncovered shifts daily at 7 AM
cron.schedule('0 7 * * *', async () => {
  const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate() + 1);
  const { data: openShifts } = await supabase.from('shifts').select('*, home:homes(name)')
    .eq('status', 'open').eq('shift_date', tomorrow.toISOString().split('T')[0]);
  for (const shift of (openShifts || [])) {
    await supabase.from('alerts').insert({
      home_id: shift.home_id, alert_type: 'shift_uncovered',
      priority: 'high', related_shift_id: shift.id,
      title: 'Uncovered Shift Tomorrow',
      message: `${shift.home?.name}: ${shift.shift_type} shift on ${shift.shift_date} has no staff assigned.`
    });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Magnify API running on port ${PORT}`));

module.exports = app;
