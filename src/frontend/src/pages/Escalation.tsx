import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  Row,
  Col,
  Table,
  Tag,
  Badge,
  Button,
  Typography,
  Timeline,
  Space,
  Tooltip,
} from 'antd';
import {
  ArrowUpOutlined,
  ArrowDownOutlined,
  WarningOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined,
  ClockCircleOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';

const { Text, Title } = Typography;

// --------------- Types ---------------

type EscalationLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

interface TriggerRow {
  key: string;
  name: string;
  currentValue: number;
  threshold: number;
  unit: string;
  active: boolean;
}

interface EscalationEvent {
  timestamp: string;
  from: EscalationLevel;
  to: EscalationLevel;
  reason: string;
  triggerValues: string;
}

// --------------- Constants ---------------

const LEVEL_META: Record<EscalationLevel, { color: string; bg: string; description: string }> = {
  LOW: {
    color: '#52c41a',
    bg: 'rgba(82, 196, 26, 0.08)',
    description: 'Normal traffic levels. Baseline learning and passive monitoring active.',
  },
  MEDIUM: {
    color: '#faad14',
    bg: 'rgba(250, 173, 20, 0.08)',
    description: 'Elevated traffic detected. Rate limiting and reputation tracking engaged.',
  },
  HIGH: {
    color: '#fa8c16',
    bg: 'rgba(250, 140, 22, 0.08)',
    description: 'Active attack in progress. Aggressive filtering, GeoIP, and payload matching enabled.',
  },
  CRITICAL: {
    color: '#f5222d',
    bg: 'rgba(245, 34, 45, 0.08)',
    description: 'Severe attack. Full scrub mode with BGP Flowspec, RTBH, and challenge-response.',
  },
};

const LEVELS: EscalationLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const LEVEL_ACTIONS: { level: EscalationLevel; actions: string[] }[] = [
  { level: 'LOW', actions: ['Baseline learning (EWMA)', 'Passive monitoring', 'Stats collection', 'Conntrack tracking'] },
  { level: 'MEDIUM', actions: ['Per-source rate limiting', 'Reputation scoring', 'SYN cookie validation', 'Adaptive thresholds'] },
  { level: 'HIGH', actions: ['Aggressive packet filtering', 'GeoIP enforcement', 'Payload signature matching', 'ACL auto-population', 'Fragment drop'] },
  { level: 'CRITICAL', actions: ['Full scrub mode', 'BGP Flowspec injection', 'RTBH blackholing', 'Challenge-response (SYN proxy)', 'Upstream notification'] },
];

// --------------- Mock data generators ---------------

const baseTriggers: TriggerRow[] = [
  { key: 'drop_ratio', name: 'Drop Ratio', currentValue: 0.12, threshold: 0.30, unit: '%', active: false },
  { key: 'zscore_pps', name: 'Z-Score PPS', currentValue: 1.8, threshold: 3.0, unit: 'sigma', active: false },
  { key: 'zscore_bps', name: 'Z-Score BPS', currentValue: 1.2, threshold: 3.0, unit: 'sigma', active: false },
  { key: 'rep_blocked', name: 'Reputation Blocked', currentValue: 420, threshold: 1000, unit: 'IPs', active: false },
  { key: 'drop_pps', name: 'Drop PPS', currentValue: 8500, threshold: 50000, unit: 'pps', active: false },
];

const mockHistory: EscalationEvent[] = [
  {
    timestamp: dayjs().subtract(4, 'hour').subtract(12, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'LOW',
    to: 'MEDIUM',
    reason: 'Z-Score PPS exceeded threshold',
    triggerValues: 'Z-Score PPS: 3.4, Drop Ratio: 0.18',
  },
  {
    timestamp: dayjs().subtract(3, 'hour').subtract(48, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'MEDIUM',
    to: 'HIGH',
    reason: 'Drop PPS and Reputation Blocked thresholds exceeded',
    triggerValues: 'Drop PPS: 62,400, Rep Blocked: 1,240',
  },
  {
    timestamp: dayjs().subtract(3, 'hour').subtract(22, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'HIGH',
    to: 'CRITICAL',
    reason: 'Drop ratio above 0.60, multiple triggers active',
    triggerValues: 'Drop Ratio: 0.63, Z-Score PPS: 8.1, Drop PPS: 245,000',
  },
  {
    timestamp: dayjs().subtract(2, 'hour').subtract(5, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'CRITICAL',
    to: 'HIGH',
    reason: 'Attack subsiding, drop ratio falling',
    triggerValues: 'Drop Ratio: 0.28, Z-Score PPS: 2.9',
  },
  {
    timestamp: dayjs().subtract(1, 'hour').subtract(30, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'HIGH',
    to: 'MEDIUM',
    reason: 'Triggers below HIGH thresholds for 5m',
    triggerValues: 'Drop PPS: 12,300, Rep Blocked: 680',
  },
  {
    timestamp: dayjs().subtract(38, 'minute').format('YYYY-MM-DD HH:mm:ss'),
    from: 'MEDIUM',
    to: 'LOW',
    reason: 'All triggers below MEDIUM thresholds for 10m',
    triggerValues: 'Z-Score PPS: 1.1, Drop Ratio: 0.05',
  },
];

// --------------- Component ---------------

const Escalation: React.FC = () => {
  const [currentLevel, setCurrentLevel] = useState<EscalationLevel>('LOW');
  const [levelSince, setLevelSince] = useState<string>(
    dayjs().subtract(38, 'minute').format('YYYY-MM-DD HH:mm:ss'),
  );
  const [triggers, setTriggers] = useState<TriggerRow[]>(baseTriggers);
  const [history] = useState<EscalationEvent[]>(mockHistory);

  // Simulate trigger value updates every 2 seconds
  const updateTriggers = useCallback(() => {
    setTriggers((prev) =>
      prev.map((t) => {
        const jitter = (Math.random() - 0.5) * t.threshold * 0.15;
        let newVal = t.currentValue + jitter;
        if (newVal < 0) newVal = Math.abs(jitter) * 0.1;
        const active = newVal >= t.threshold;
        return { ...t, currentValue: parseFloat(newVal.toFixed(t.unit === '%' ? 4 : 1)), active };
      }),
    );
  }, []);

  useEffect(() => {
    const interval = setInterval(updateTriggers, 2000);
    return () => clearInterval(interval);
  }, [updateTriggers]);

  const handleOverride = (level: EscalationLevel) => {
    setCurrentLevel(level);
    setLevelSince(dayjs().format('YYYY-MM-DD HH:mm:ss'));
  };

  const meta = LEVEL_META[currentLevel];

  // --------------- Table columns ---------------

  const triggerColumns: ColumnsType<TriggerRow> = [
    {
      title: 'Trigger',
      dataIndex: 'name',
      key: 'name',
      render: (name: string) => <Text strong style={{ color: 'rgba(255,255,255,0.85)' }}>{name}</Text>,
    },
    {
      title: 'Current Value',
      dataIndex: 'currentValue',
      key: 'currentValue',
      render: (val: number, record: TriggerRow) => {
        const ratio = val / record.threshold;
        let color = '#52c41a';
        if (ratio > 0.8) color = '#faad14';
        if (ratio >= 1) color = '#f5222d';
        const display = record.unit === '%' ? `${(val * 100).toFixed(1)}%` : `${val.toLocaleString()} ${record.unit}`;
        return <Text style={{ color, fontFamily: 'monospace' }}>{display}</Text>;
      },
    },
    {
      title: 'Threshold',
      dataIndex: 'threshold',
      key: 'threshold',
      render: (val: number, record: TriggerRow) => {
        const display = record.unit === '%' ? `${(val * 100).toFixed(0)}%` : `${val.toLocaleString()} ${record.unit}`;
        return <Text style={{ color: 'rgba(255,255,255,0.45)', fontFamily: 'monospace' }}>{display}</Text>;
      },
    },
    {
      title: 'Status',
      dataIndex: 'active',
      key: 'active',
      width: 120,
      render: (active: boolean) =>
        active ? (
          <Badge status="error" text={<Text style={{ color: '#f5222d' }}>Active</Text>} />
        ) : (
          <Badge status="default" text={<Text style={{ color: 'rgba(255,255,255,0.45)' }}>Inactive</Text>} />
        ),
    },
  ];

  const actionColumns: ColumnsType<{ level: EscalationLevel; actions: string[] }> = [
    {
      title: 'Level',
      dataIndex: 'level',
      key: 'level',
      width: 120,
      render: (level: EscalationLevel) => (
        <Tag
          color={LEVEL_META[level].color}
          style={{
            fontWeight: 600,
            borderColor: LEVEL_META[level].color,
            background: LEVEL_META[level].bg,
          }}
        >
          {level}
        </Tag>
      ),
    },
    {
      title: 'Active Mitigations',
      dataIndex: 'actions',
      key: 'actions',
      render: (actions: string[]) => (
        <Space wrap size={[4, 4]}>
          {actions.map((a) => (
            <Tag key={a} style={{ margin: 0 }}>{a}</Tag>
          ))}
        </Space>
      ),
    },
  ];

  // --------------- Timeline ---------------

  const timelineItems = history
    .slice()
    .reverse()
    .map((evt, idx) => {
      const toMeta = LEVEL_META[evt.to];
      const isUp = LEVELS.indexOf(evt.to) > LEVELS.indexOf(evt.from);
      return {
        key: idx,
        color: toMeta.color,
        dot: isUp ? (
          <ArrowUpOutlined style={{ color: toMeta.color, fontSize: 14 }} />
        ) : (
          <ArrowDownOutlined style={{ color: toMeta.color, fontSize: 14 }} />
        ),
        children: (
          <div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 4 }}>
              <Tag
                color={LEVEL_META[evt.from].color}
                style={{ borderColor: LEVEL_META[evt.from].color, background: LEVEL_META[evt.from].bg }}
              >
                {evt.from}
              </Tag>
              <Text style={{ color: 'rgba(255,255,255,0.45)' }}>&rarr;</Text>
              <Tag
                color={toMeta.color}
                style={{ borderColor: toMeta.color, background: toMeta.bg }}
              >
                {evt.to}
              </Tag>
              <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 12 }}>{evt.timestamp}</Text>
            </div>
            <Text style={{ color: 'rgba(255,255,255,0.65)', fontSize: 13 }}>{evt.reason}</Text>
            <br />
            <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 12, fontFamily: 'monospace' }}>
              {evt.triggerValues}
            </Text>
          </div>
        ),
      };
    });

  // --------------- Render ---------------

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <ThunderboltOutlined style={{ fontSize: 18, color: '#1668dc' }} />
        <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
          Auto-Escalation Engine
        </Text>
      </div>

      {/* Row 1: Current Level + Trigger Table */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={8}>
          <Card
            style={{
              borderColor: meta.color,
              borderWidth: 2,
              background: meta.bg,
              height: '100%',
            }}
            bodyStyle={{ textAlign: 'center', padding: 32 }}
          >
            <div style={{ marginBottom: 16 }}>
              {currentLevel === 'LOW' && <CheckCircleOutlined style={{ fontSize: 48, color: meta.color }} />}
              {currentLevel === 'MEDIUM' && <ExclamationCircleOutlined style={{ fontSize: 48, color: meta.color }} />}
              {currentLevel === 'HIGH' && <WarningOutlined style={{ fontSize: 48, color: meta.color }} />}
              {currentLevel === 'CRITICAL' && <WarningOutlined style={{ fontSize: 48, color: meta.color }} />}
            </div>
            <Title level={2} style={{ color: meta.color, margin: 0 }}>
              {currentLevel}
            </Title>
            <Text style={{ color: 'rgba(255,255,255,0.65)', display: 'block', margin: '12px 0' }}>
              {meta.description}
            </Text>
            <div style={{ marginBottom: 16 }}>
              <ClockCircleOutlined style={{ color: 'rgba(255,255,255,0.35)', marginRight: 6 }} />
              <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>Since {levelSince}</Text>
            </div>

            <Text
              style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12, display: 'block', marginBottom: 8 }}
            >
              Manual Override
            </Text>
            <Space wrap>
              {LEVELS.map((lvl) => (
                <Tooltip title={`Force escalation to ${lvl}`} key={lvl}>
                  <Button
                    size="small"
                    type={currentLevel === lvl ? 'primary' : 'default'}
                    style={{
                      borderColor: LEVEL_META[lvl].color,
                      color: currentLevel === lvl ? '#fff' : LEVEL_META[lvl].color,
                      background: currentLevel === lvl ? LEVEL_META[lvl].color : 'transparent',
                    }}
                    onClick={() => handleOverride(lvl)}
                  >
                    {lvl}
                  </Button>
                </Tooltip>
              ))}
            </Space>
          </Card>
        </Col>

        <Col xs={24} lg={16}>
          <Card title="Trigger Status" size="small">
            <Table
              columns={triggerColumns}
              dataSource={triggers}
              rowKey="key"
              size="small"
              pagination={false}
            />
          </Card>
        </Col>
      </Row>

      {/* Row 2: Timeline + Level Actions Reference */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Escalation Timeline" size="small" style={{ height: '100%' }}>
            <Timeline items={timelineItems} />
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card title="Level Actions Reference" size="small" style={{ height: '100%' }}>
            <Table
              columns={actionColumns}
              dataSource={LEVEL_ACTIONS}
              rowKey="level"
              size="small"
              pagination={false}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Escalation;
