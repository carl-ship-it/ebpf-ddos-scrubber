import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Card,
  Row,
  Col,
  Table,
  Tag,
  Switch,
  Typography,
  Progress,
  Statistic,
  Space,
} from 'antd';
import {
  LineChartOutlined,
  ExperimentOutlined,
} from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import type { ColumnsType } from 'antd/es/table';
import dayjs from 'dayjs';

const { Text } = Typography;

// --------------- Types ---------------

interface BaselinePoint {
  time: string;
  actual: number;
  baseline: number;
  upper: number;
  lower: number;
  isAnomaly: boolean;
}

interface RateLimitRow {
  key: string;
  protocol: string;
  baseline: number;
  adaptive: number;
  override: number | null;
}

// --------------- Mock data generators ---------------

function generateBaselineHistory(count: number): BaselinePoint[] {
  const points: BaselinePoint[] = [];
  const now = dayjs();
  let baselinePps = 45000;
  const stddev = 8000;

  for (let i = count - 1; i >= 0; i--) {
    const t = now.subtract(i, 'second').format('HH:mm:ss');
    // Simulate EWMA baseline with slow drift
    baselinePps += (Math.random() - 0.5) * 400;
    if (baselinePps < 20000) baselinePps = 20000;
    if (baselinePps > 80000) baselinePps = 80000;

    // Actual traffic with occasional spikes
    let actual = baselinePps + (Math.random() - 0.5) * stddev * 2;
    const spike = Math.random();
    if (spike > 0.92) {
      actual = baselinePps + stddev * (3.5 + Math.random() * 3);
    }
    if (actual < 0) actual = 500;

    const upper = baselinePps + 2 * stddev;
    const lower = Math.max(0, baselinePps - 2 * stddev);
    const zScore = Math.abs(actual - baselinePps) / stddev;

    points.push({
      time: t,
      actual: Math.round(actual),
      baseline: Math.round(baselinePps),
      upper: Math.round(upper),
      lower: Math.round(lower),
      isAnomaly: zScore > 3,
    });
  }
  return points;
}

const initialHistory = generateBaselineHistory(60);

// --------------- Component ---------------

const Baseline: React.FC = () => {
  const [history, setHistory] = useState<BaselinePoint[]>(initialHistory);
  const [adaptiveEnabled, setAdaptiveEnabled] = useState(true);
  const [learningSamples, setLearningSamples] = useState(247);
  const baselineRef = useRef(history[history.length - 1]?.baseline ?? 45000);

  // Compute live metrics from latest point
  const latest = history[history.length - 1];
  const stddev = 8000;
  const zScorePps = latest ? Math.abs(latest.actual - latest.baseline) / stddev : 0;
  const zScoreBps = Math.max(0, zScorePps * 0.85 + (Math.random() - 0.5) * 0.4);
  const anomalyScore = Math.min(100, Math.round(zScorePps * 18 + zScoreBps * 12));

  // Add new data point every 2 seconds
  const tick = useCallback(() => {
    setHistory((prev) => {
      const lastBaseline = baselineRef.current;
      const drift = (Math.random() - 0.5) * 400;
      let newBaseline = lastBaseline + drift;
      if (newBaseline < 20000) newBaseline = 20000;
      if (newBaseline > 80000) newBaseline = 80000;
      baselineRef.current = newBaseline;

      let actual = newBaseline + (Math.random() - 0.5) * stddev * 2;
      if (Math.random() > 0.92) {
        actual = newBaseline + stddev * (3.5 + Math.random() * 3);
      }
      if (actual < 0) actual = 500;

      const upper = newBaseline + 2 * stddev;
      const lower = Math.max(0, newBaseline - 2 * stddev);
      const z = Math.abs(actual - newBaseline) / stddev;

      const point: BaselinePoint = {
        time: dayjs().format('HH:mm:ss'),
        actual: Math.round(actual),
        baseline: Math.round(newBaseline),
        upper: Math.round(upper),
        lower: Math.round(lower),
        isAnomaly: z > 3,
      };

      const next = [...prev.slice(-59), point];
      return next;
    });

    setLearningSamples((s) => Math.min(300, s + 1));
  }, []);

  useEffect(() => {
    const interval = setInterval(tick, 2000);
    return () => clearInterval(interval);
  }, [tick]);

  // --------------- Chart options ---------------

  const anomalyPoints = history.filter((p) => p.isAnomaly);

  const chartOption = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis' as const,
      backgroundColor: '#1f1f1f',
      borderColor: '#424242',
      textStyle: { color: 'rgba(255,255,255,0.85)' },
    },
    legend: {
      data: ['Actual PPS', 'Baseline (EWMA)', 'Anomaly'],
      textStyle: { color: 'rgba(255,255,255,0.65)' },
      top: 0,
    },
    grid: { left: 60, right: 20, top: 40, bottom: 30 },
    xAxis: {
      type: 'category' as const,
      data: history.map((p) => p.time),
      axisLabel: { color: 'rgba(255,255,255,0.45)', fontSize: 10 },
      axisLine: { lineStyle: { color: '#424242' } },
    },
    yAxis: {
      type: 'value' as const,
      axisLabel: {
        color: 'rgba(255,255,255,0.45)',
        formatter: (v: number) => (v >= 1000 ? `${(v / 1000).toFixed(0)}K` : String(v)),
      },
      splitLine: { lineStyle: { color: '#303030' } },
    },
    series: [
      // Band: upper bound (visually transparent above baseline band)
      {
        name: '+2 Stddev',
        type: 'line',
        data: history.map((p) => p.upper),
        lineStyle: { opacity: 0 },
        areaStyle: { color: 'rgba(255,255,255,0.04)' },
        symbol: 'none',
        stack: 'band',
        silent: true,
        z: 1,
      },
      // Band: lower bound fill
      {
        name: '-2 Stddev',
        type: 'line',
        data: history.map((p) => p.lower),
        lineStyle: { opacity: 0 },
        areaStyle: { color: 'rgba(255,255,255,0.04)', opacity: 1 },
        symbol: 'none',
        silent: true,
        z: 1,
      },
      // Baseline
      {
        name: 'Baseline (EWMA)',
        type: 'line',
        data: history.map((p) => p.baseline),
        lineStyle: { color: '#52c41a', type: 'dashed' as const, width: 2 },
        itemStyle: { color: '#52c41a' },
        symbol: 'none',
        z: 2,
      },
      // Actual
      {
        name: 'Actual PPS',
        type: 'line',
        data: history.map((p) => p.actual),
        lineStyle: { color: '#1668dc', width: 2 },
        itemStyle: { color: '#1668dc' },
        symbol: 'none',
        z: 3,
      },
      // Anomaly points
      {
        name: 'Anomaly',
        type: 'scatter',
        data: anomalyPoints.map((p) => [p.time, p.actual]),
        itemStyle: { color: '#f5222d' },
        symbolSize: 10,
        z: 4,
      },
    ],
  };

  // --------------- Protocol distribution ---------------

  const protoPieOption = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item' as const,
      backgroundColor: '#1f1f1f',
      borderColor: '#424242',
      textStyle: { color: 'rgba(255,255,255,0.85)' },
    },
    legend: {
      orient: 'vertical' as const,
      right: 10,
      top: 'center' as const,
      textStyle: { color: 'rgba(255,255,255,0.65)', fontSize: 11 },
    },
    series: [
      {
        name: 'Protocol',
        type: 'pie',
        radius: ['40%', '70%'],
        center: ['35%', '50%'],
        avoidLabelOverlap: false,
        label: { show: false },
        data: [
          { value: 42, name: 'TCP', itemStyle: { color: '#1668dc' } },
          { value: 31, name: 'UDP', itemStyle: { color: '#fa8c16' } },
          { value: 8, name: 'ICMP', itemStyle: { color: '#52c41a' } },
          { value: 15, name: 'DNS', itemStyle: { color: '#722ed1' } },
          { value: 4, name: 'Other', itemStyle: { color: '#8c8c8c' } },
        ],
      },
      {
        name: 'Baseline',
        type: 'pie',
        radius: ['20%', '35%'],
        center: ['35%', '50%'],
        avoidLabelOverlap: false,
        label: { show: false },
        data: [
          { value: 48, name: 'TCP (baseline)', itemStyle: { color: 'rgba(22, 104, 220, 0.4)' } },
          { value: 25, name: 'UDP (baseline)', itemStyle: { color: 'rgba(250, 140, 22, 0.4)' } },
          { value: 10, name: 'ICMP (baseline)', itemStyle: { color: 'rgba(82, 196, 26, 0.4)' } },
          { value: 13, name: 'DNS (baseline)', itemStyle: { color: 'rgba(114, 46, 209, 0.4)' } },
          { value: 4, name: 'Other (baseline)', itemStyle: { color: 'rgba(140, 140, 140, 0.4)' } },
        ],
      },
    ],
  };

  // --------------- Adaptive rate limits ---------------

  const rateLimits: RateLimitRow[] = [
    { key: 'syn', protocol: 'SYN PPS', baseline: 1200, adaptive: adaptiveEnabled ? 1440 : 1200, override: null },
    { key: 'udp', protocol: 'UDP PPS', baseline: 15000, adaptive: adaptiveEnabled ? 18200 : 15000, override: null },
    { key: 'icmp', protocol: 'ICMP PPS', baseline: 200, adaptive: adaptiveEnabled ? 260 : 200, override: null },
    { key: 'global', protocol: 'Global PPS', baseline: 85000, adaptive: adaptiveEnabled ? 102000 : 85000, override: null },
  ];

  const rateLimitColumns: ColumnsType<RateLimitRow> = [
    {
      title: 'Protocol',
      dataIndex: 'protocol',
      key: 'protocol',
      render: (v: string) => <Text strong style={{ color: 'rgba(255,255,255,0.85)' }}>{v}</Text>,
    },
    {
      title: 'Baseline',
      dataIndex: 'baseline',
      key: 'baseline',
      render: (v: number) => (
        <Text style={{ color: 'rgba(255,255,255,0.65)', fontFamily: 'monospace' }}>
          {v.toLocaleString()}
        </Text>
      ),
    },
    {
      title: 'Adaptive',
      dataIndex: 'adaptive',
      key: 'adaptive',
      render: (v: number, record: RateLimitRow) => {
        const diff = v - record.baseline;
        return (
          <Space>
            <Text style={{ color: adaptiveEnabled ? '#52c41a' : 'rgba(255,255,255,0.45)', fontFamily: 'monospace' }}>
              {v.toLocaleString()}
            </Text>
            {adaptiveEnabled && diff !== 0 && (
              <Tag color={diff > 0 ? 'green' : 'red'} style={{ margin: 0 }}>
                {diff > 0 ? '+' : ''}{diff.toLocaleString()}
              </Tag>
            )}
          </Space>
        );
      },
    },
    {
      title: 'Override',
      dataIndex: 'override',
      key: 'override',
      render: (v: number | null) => (
        <Text style={{ color: 'rgba(255,255,255,0.35)', fontFamily: 'monospace' }}>
          {v !== null ? v.toLocaleString() : '--'}
        </Text>
      ),
    },
  ];

  // --------------- Z-Score color helper ---------------

  function zColor(z: number): string {
    if (z < 2) return '#52c41a';
    if (z < 3) return '#faad14';
    return '#f5222d';
  }

  // --------------- Render ---------------

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <LineChartOutlined style={{ fontSize: 18, color: '#1668dc' }} />
        <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
          Baseline &amp; Anomaly Detection
        </Text>
      </div>

      {/* Anomaly Metric Cards */}
      <Row gutter={[12, 12]}>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Z-Score PPS"
              value={zScorePps.toFixed(2)}
              suffix="&sigma;"
              valueStyle={{ color: zColor(zScorePps), fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Z-Score BPS"
              value={zScoreBps.toFixed(2)}
              suffix="&sigma;"
              valueStyle={{ color: zColor(zScoreBps), fontFamily: 'monospace' }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <Statistic
              title="Anomaly Score"
              value={anomalyScore}
              suffix="/ 100"
              valueStyle={{
                color: anomalyScore < 40 ? '#52c41a' : anomalyScore < 70 ? '#faad14' : '#f5222d',
                fontFamily: 'monospace',
              }}
            />
          </Card>
        </Col>
        <Col xs={12} md={6}>
          <Card size="small">
            <div style={{ marginBottom: 4 }}>
              <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>Learning Status</Text>
            </div>
            <ExperimentOutlined style={{ color: '#1668dc', marginRight: 8 }} />
            <Text style={{ color: 'rgba(255,255,255,0.85)', fontFamily: 'monospace' }}>
              {learningSamples} / 300
            </Text>
            <Progress
              percent={Math.round((learningSamples / 300) * 100)}
              size="small"
              strokeColor={learningSamples >= 300 ? '#52c41a' : '#1668dc'}
              showInfo={false}
              style={{ marginTop: 8 }}
            />
          </Card>
        </Col>
      </Row>

      {/* Main Chart */}
      <Card title="Baseline vs Actual Traffic (PPS)" size="small">
        <ReactECharts option={chartOption} style={{ height: 340 }} notMerge />
      </Card>

      {/* Row 3: Rate Limits + Protocol Distribution */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card
            title="Adaptive Rate Limits"
            size="small"
            extra={
              <Space>
                <Text style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>Adaptive Mode</Text>
                <Switch
                  checked={adaptiveEnabled}
                  onChange={setAdaptiveEnabled}
                  checkedChildren="ON"
                  unCheckedChildren="OFF"
                  size="small"
                />
              </Space>
            }
          >
            <Table
              columns={rateLimitColumns}
              dataSource={rateLimits}
              rowKey="key"
              size="small"
              pagination={false}
            />
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card
            title="Protocol Distribution"
            size="small"
            extra={
              <Space size={12}>
                <Tag color="#1668dc" style={{ margin: 0 }}>Current (outer)</Tag>
                <Tag style={{ margin: 0, opacity: 0.5 }}>Baseline (inner)</Tag>
              </Space>
            }
          >
            <ReactECharts option={protoPieOption} style={{ height: 260 }} />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Baseline;
