import React, { useState, useMemo, useCallback } from 'react';
import {
  Card,
  Table,
  Row,
  Col,
  Statistic,
  Switch,
  Slider,
  Button,
  Tag,
  Space,
  Typography,
  Progress,
  message,
  Divider,
} from 'antd';
import {
  SafetyOutlined,
  StopOutlined,
  BarChartOutlined,
  BugOutlined,
  RadarChartOutlined,
  LockOutlined,
  UnlockOutlined,
} from '@ant-design/icons';
import type { ColumnsType } from 'antd/es/table';
import ReactECharts from 'echarts-for-react';
import dayjs from 'dayjs';
import { formatCount } from '../utils';

const { Text } = Typography;

// --- Types ---

type ReputationStatus = 'blocked' | 'active' | 'clean';

interface ReputationEntry {
  key: number;
  rank: number;
  ip: string;
  score: number;
  packets: number;
  drops: number;
  violations: number;
  status: ReputationStatus;
  firstSeen: string;
  lastSeen: string;
}

// --- Mock data generators ---

function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function randomIP(): string {
  return `${randomInt(1, 223)}.${randomInt(0, 255)}.${randomInt(0, 255)}.${randomInt(1, 254)}`;
}

function randomTimestamp(daysBack: number): string {
  const now = dayjs();
  const offset = randomInt(0, daysBack * 24 * 60);
  return now.subtract(offset, 'minute').format('YYYY-MM-DD HH:mm:ss');
}

function generateMockOffenders(blockThreshold: number): ReputationEntry[] {
  const entries: ReputationEntry[] = [];
  for (let i = 0; i < 15; i++) {
    const score = randomInt(50, 980);
    const packets = randomInt(1000, 8_000_000);
    const drops = score > blockThreshold ? randomInt(Math.floor(packets * 0.3), packets) : randomInt(0, Math.floor(packets * 0.1));
    const violations = randomInt(0, Math.floor(score / 30));
    let status: ReputationStatus;
    if (score >= blockThreshold) status = 'blocked';
    else if (score >= 200) status = 'active';
    else status = 'clean';
    const firstSeen = randomTimestamp(30);
    const lastSeen = randomTimestamp(2);

    entries.push({
      key: i,
      rank: i + 1,
      ip: randomIP(),
      score,
      packets,
      drops,
      violations,
      status,
      firstSeen,
      lastSeen,
    });
  }
  // Sort descending by score, reassign ranks
  entries.sort((a, b) => b.score - a.score);
  entries.forEach((e, idx) => {
    e.rank = idx + 1;
    e.key = idx;
  });
  return entries;
}

// Generate a score distribution for the histogram
function generateScoreDistribution(offenders: ReputationEntry[]): number[] {
  const buckets = new Array(10).fill(0);
  // Offenders contribute to their bucket
  for (const o of offenders) {
    const idx = Math.min(Math.floor(o.score / 100), 9);
    buckets[idx] += 1;
  }
  // Add random background IPs to fill the histogram nicely
  buckets[0] += randomInt(300, 600);   // 0-100  (clean)
  buckets[1] += randomInt(180, 350);   // 100-200
  buckets[2] += randomInt(90, 200);    // 200-300
  buckets[3] += randomInt(60, 140);    // 300-400
  buckets[4] += randomInt(30, 90);     // 400-500
  buckets[5] += randomInt(15, 50);     // 500-600
  buckets[6] += randomInt(8, 30);      // 600-700
  buckets[7] += randomInt(4, 18);      // 700-800
  buckets[8] += randomInt(2, 10);      // 800-900
  buckets[9] += randomInt(0, 5);       // 900-1000
  return buckets;
}

// --- Status meta ---

const STATUS_META: Record<ReputationStatus, { color: string; label: string }> = {
  blocked: { color: 'red', label: 'Blocked' },
  active: { color: 'orange', label: 'Active' },
  clean: { color: 'green', label: 'Clean' },
};

// --- Component ---

const ReputationPage: React.FC = () => {
  // Config state
  const [enabled, setEnabled] = useState(true);
  const [blockThreshold, setBlockThreshold] = useState(500);
  const [decayRate, setDecayRate] = useState(5);
  const [portScanDetection, setPortScanDetection] = useState(true);
  const [autoBlock, setAutoBlock] = useState(true);

  // Offenders (regenerated once; stable for the session)
  const [offenders, setOffenders] = useState<ReputationEntry[]>(() =>
    generateMockOffenders(500),
  );

  // Recompute statuses when threshold changes
  const adjustedOffenders = useMemo(() => {
    return offenders.map((o) => {
      let status: ReputationStatus;
      if (o.score >= blockThreshold) status = 'blocked';
      else if (o.score >= 200) status = 'active';
      else status = 'clean';
      return { ...o, status };
    });
  }, [offenders, blockThreshold]);

  // Stats
  const stats = useMemo(() => {
    const totalIPs = randomInt(8400, 12000);
    const autoBlocked = adjustedOffenders.filter((o) => o.status === 'blocked').length + randomInt(20, 80);
    const avgScore = Math.round(
      adjustedOffenders.reduce((acc, o) => acc + o.score, 0) / adjustedOffenders.length,
    );
    const portScans = randomInt(40, 200);
    return { totalIPs, autoBlocked, avgScore, portScans };
  }, [adjustedOffenders]);

  // Score distribution for chart
  const distribution = useMemo(
    () => generateScoreDistribution(adjustedOffenders),
    [adjustedOffenders],
  );

  // Manual block / unblock
  const handleToggleBlock = useCallback(
    (ip: string, currentStatus: ReputationStatus) => {
      setOffenders((prev) =>
        prev.map((o) => {
          if (o.ip !== ip) return o;
          if (currentStatus === 'blocked') {
            return { ...o, score: Math.max(o.score - 300, 0), status: 'active' as ReputationStatus };
          }
          return { ...o, score: 1000, status: 'blocked' as ReputationStatus };
        }),
      );
      if (currentStatus === 'blocked') {
        message.success(`${ip} unblocked`);
      } else {
        message.success(`${ip} manually blocked`);
      }
    },
    [],
  );

  // Score color helper
  const scoreColor = (score: number): string => {
    if (score >= 800) return '#f5222d';
    if (score >= 600) return '#fa541c';
    if (score >= 400) return '#fa8c16';
    if (score >= 200) return '#fadb14';
    return '#52c41a';
  };

  // ECharts histogram option
  const chartOption = useMemo(
    () => ({
      backgroundColor: 'transparent',
      tooltip: {
        trigger: 'axis' as const,
        axisPointer: { type: 'shadow' as const },
        backgroundColor: '#1f1f1f',
        borderColor: '#424242',
        textStyle: { color: 'rgba(255,255,255,0.85)' },
      },
      grid: { left: 50, right: 30, top: 40, bottom: 40 },
      xAxis: {
        type: 'category' as const,
        data: [
          '0-100',
          '100-200',
          '200-300',
          '300-400',
          '400-500',
          '500-600',
          '600-700',
          '700-800',
          '800-900',
          '900-1000',
        ],
        axisLabel: { color: 'rgba(255,255,255,0.55)', fontSize: 11 },
        axisLine: { lineStyle: { color: '#424242' } },
        name: 'Score Range',
        nameTextStyle: { color: 'rgba(255,255,255,0.45)', fontSize: 11 },
      },
      yAxis: {
        type: 'value' as const,
        axisLabel: { color: 'rgba(255,255,255,0.55)', fontSize: 11 },
        splitLine: { lineStyle: { color: '#303030' } },
        name: 'IP Count',
        nameTextStyle: { color: 'rgba(255,255,255,0.45)', fontSize: 11 },
      },
      series: [
        {
          name: 'IPs',
          type: 'bar',
          data: distribution.map((val, idx) => ({
            value: val,
            itemStyle: {
              color:
                idx * 100 >= blockThreshold
                  ? 'rgba(245, 34, 45, 0.7)'
                  : 'rgba(22, 104, 220, 0.7)',
              borderRadius: [3, 3, 0, 0],
            },
          })),
          barWidth: '60%',
        },
        {
          name: 'Block Threshold',
          type: 'line',
          markLine: {
            silent: true,
            symbol: 'none',
            lineStyle: { color: '#f5222d', type: 'dashed' as const, width: 2 },
            data: [
              {
                xAxis: `${blockThreshold}-${blockThreshold + 100}`,
                label: {
                  formatter: `Threshold: ${blockThreshold}`,
                  color: '#f5222d',
                  fontSize: 11,
                },
              },
            ],
          },
          data: [],
        },
      ],
    }),
    [distribution, blockThreshold],
  );

  // Table columns
  const columns: ColumnsType<ReputationEntry> = [
    {
      title: '#',
      dataIndex: 'rank',
      key: 'rank',
      width: 50,
      render: (rank: number) => (
        <Text style={{ color: 'rgba(255,255,255,0.45)' }}>{rank}</Text>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
      width: 150,
      render: (ip: string) => <Text code>{ip}</Text>,
    },
    {
      title: 'Score',
      dataIndex: 'score',
      key: 'score',
      width: 180,
      sorter: (a, b) => a.score - b.score,
      defaultSortOrder: 'descend',
      render: (score: number) => (
        <Space direction="vertical" size={0} style={{ width: '100%' }}>
          <Text strong style={{ color: scoreColor(score), fontFamily: 'monospace', fontSize: 13 }}>
            {score}
          </Text>
          <Progress
            percent={score / 10}
            showInfo={false}
            size="small"
            strokeColor={scoreColor(score)}
            trailColor="rgba(255,255,255,0.08)"
            style={{ marginBottom: 0, width: 120 }}
          />
        </Space>
      ),
    },
    {
      title: 'Packets',
      dataIndex: 'packets',
      key: 'packets',
      width: 100,
      sorter: (a, b) => a.packets - b.packets,
      render: (val: number) => (
        <Text style={{ fontFamily: 'monospace', color: 'rgba(255,255,255,0.85)' }}>
          {formatCount(val)}
        </Text>
      ),
    },
    {
      title: 'Drops',
      dataIndex: 'drops',
      key: 'drops',
      width: 100,
      sorter: (a, b) => a.drops - b.drops,
      render: (val: number) => (
        <Text style={{ fontFamily: 'monospace', color: val > 0 ? '#f5222d' : 'rgba(255,255,255,0.45)' }}>
          {formatCount(val)}
        </Text>
      ),
    },
    {
      title: 'Violations',
      dataIndex: 'violations',
      key: 'violations',
      width: 90,
      sorter: (a, b) => a.violations - b.violations,
      render: (val: number) => (
        <Text style={{ fontFamily: 'monospace', color: val > 10 ? '#fa8c16' : 'rgba(255,255,255,0.65)' }}>
          {val}
        </Text>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      filters: [
        { text: 'Blocked', value: 'blocked' },
        { text: 'Active', value: 'active' },
        { text: 'Clean', value: 'clean' },
      ],
      onFilter: (value, record) => record.status === value,
      render: (status: ReputationStatus) => {
        const meta = STATUS_META[status];
        return <Tag color={meta.color}>{meta.label}</Tag>;
      },
    },
    {
      title: 'First Seen',
      dataIndex: 'firstSeen',
      key: 'firstSeen',
      width: 160,
      render: (val: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.55)', fontSize: 12 }}>{val}</Text>
      ),
    },
    {
      title: 'Last Seen',
      dataIndex: 'lastSeen',
      key: 'lastSeen',
      width: 160,
      render: (val: string) => (
        <Text style={{ color: 'rgba(255,255,255,0.55)', fontSize: 12 }}>{val}</Text>
      ),
    },
    {
      title: 'Action',
      key: 'action',
      width: 110,
      render: (_, record) => (
        <Button
          type={record.status === 'blocked' ? 'default' : 'primary'}
          danger={record.status !== 'blocked'}
          size="small"
          icon={record.status === 'blocked' ? <UnlockOutlined /> : <LockOutlined />}
          onClick={() => handleToggleBlock(record.ip, record.status)}
          disabled={!enabled}
        >
          {record.status === 'blocked' ? 'Unblock' : 'Block'}
        </Button>
      ),
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Stats row */}
      <Row gutter={[12, 12]}>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Total IPs Tracked"
              value={stats.totalIPs}
              valueStyle={{ color: '#1668dc', fontSize: 22 }}
              prefix={<RadarChartOutlined />}
              formatter={(val) => formatCount(val as number)}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Auto-Blocked IPs"
              value={stats.autoBlocked}
              valueStyle={{ color: '#f5222d', fontSize: 22 }}
              prefix={<StopOutlined />}
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Average Score"
              value={stats.avgScore}
              valueStyle={{ color: '#fa8c16', fontSize: 22 }}
              prefix={<BarChartOutlined />}
              suffix="/ 1000"
            />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card size="small">
            <Statistic
              title="Port Scans Detected"
              value={stats.portScans}
              valueStyle={{ color: '#722ed1', fontSize: 22 }}
              prefix={<BugOutlined />}
            />
          </Card>
        </Col>
      </Row>

      {/* Configuration + Score Distribution */}
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={8}>
          <Card
            title={
              <Space>
                <SafetyOutlined style={{ color: '#1668dc' }} />
                <span>Reputation Configuration</span>
              </Space>
            }
            size="small"
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text style={{ color: 'rgba(255,255,255,0.85)' }}>Enable Reputation System</Text>
                <Switch
                  checked={enabled}
                  onChange={(checked) => {
                    setEnabled(checked);
                    message.info(checked ? 'Reputation system enabled' : 'Reputation system disabled');
                  }}
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                />
              </div>

              <Divider style={{ margin: 0 }} />

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: 'rgba(255,255,255,0.65)' }}>Block Threshold</Text>
                  <Text strong style={{ color: '#f5222d' }}>{blockThreshold}</Text>
                </div>
                <Slider
                  min={0}
                  max={1000}
                  step={10}
                  value={blockThreshold}
                  onChange={setBlockThreshold}
                  disabled={!enabled}
                  tooltip={{ formatter: (val) => `${val} / 1000` }}
                  styles={{
                    track: { background: '#f5222d' },
                  }}
                />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: 'rgba(255,255,255,0.65)' }}>Decay Rate (pts/hour)</Text>
                  <Text strong style={{ color: '#1668dc' }}>{decayRate}</Text>
                </div>
                <Slider
                  min={1}
                  max={50}
                  value={decayRate}
                  onChange={setDecayRate}
                  disabled={!enabled}
                  tooltip={{ formatter: (val) => `${val} pts/hr` }}
                />
              </div>

              <Divider style={{ margin: 0 }} />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text style={{ color: 'rgba(255,255,255,0.85)' }}>Port Scan Detection</Text>
                <Switch
                  checked={portScanDetection}
                  onChange={(checked) => {
                    setPortScanDetection(checked);
                    message.info(checked ? 'Port scan detection enabled' : 'Port scan detection disabled');
                  }}
                  disabled={!enabled}
                  size="small"
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Text style={{ color: 'rgba(255,255,255,0.85)' }}>Auto-Block on Threshold</Text>
                <Switch
                  checked={autoBlock}
                  onChange={(checked) => {
                    setAutoBlock(checked);
                    message.info(checked ? 'Auto-block enabled' : 'Auto-block disabled');
                  }}
                  disabled={!enabled}
                  size="small"
                />
              </div>
            </div>
          </Card>
        </Col>

        <Col xs={24} lg={16}>
          <Card
            title={
              <Space>
                <BarChartOutlined style={{ color: '#1668dc' }} />
                <span>Score Distribution</span>
              </Space>
            }
            size="small"
          >
            <ReactECharts
              option={chartOption}
              style={{ height: 280 }}
              opts={{ renderer: 'canvas' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Top Offenders Table */}
      <Card
        title={
          <Space>
            <StopOutlined style={{ color: '#f5222d' }} />
            <span>Top Offenders</span>
            <Tag color="red">{adjustedOffenders.filter((o) => o.status === 'blocked').length} blocked</Tag>
          </Space>
        }
        size="small"
      >
        <Table
          columns={columns}
          dataSource={adjustedOffenders}
          rowKey="key"
          size="small"
          pagination={false}
          scroll={{ x: 1200 }}
          style={{ opacity: enabled ? 1 : 0.45 }}
          rowClassName={(record) =>
            record.status === 'blocked' ? 'rep-row-blocked' : ''
          }
        />
      </Card>

      {/* Inline styles for row highlighting */}
      <style>{`
        .rep-row-blocked td {
          background: rgba(245, 34, 45, 0.06) !important;
        }
      `}</style>
    </div>
  );
};

export default ReputationPage;
