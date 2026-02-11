import React, { useState } from 'react';
import { Row, Col, Segmented, Typography, Badge } from 'antd';
import {
  DashboardOutlined,
} from '@ant-design/icons';
import StatsCards from '../components/StatsCards';
import TrafficChart from '../components/TrafficChart';
import AttackPanel from '../components/AttackPanel';
import EventTable from '../components/EventTable';
import ThreatGauge from '../components/ThreatGauge';
import TopAttackers from '../components/TopAttackers';
import ProtocolBreakdown from '../components/ProtocolBreakdown';
import MitigationTimeline from '../components/MitigationTimeline';
import { useStore } from '../store';

const { Text } = Typography;

const Dashboard: React.FC = () => {
  const [chartMode, setChartMode] = useState<'pps' | 'bps'>('pps');
  const connected = useStore((s) => s.connected);
  const status = useStore((s) => s.status);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <DashboardOutlined style={{ fontSize: 18, color: '#1668dc' }} />
          <Text strong style={{ fontSize: 16, color: 'rgba(255,255,255,0.85)' }}>
            DDoS Scrubber Dashboard
          </Text>
          {status && (
            <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 12 }}>
              {status.interfaceName} / XDP {status.xdpMode} / v{status.version}
            </Text>
          )}
        </div>
        <Badge status={connected ? 'success' : 'error'} text={
          <Text style={{ color: connected ? '#52c41a' : '#f5222d', fontSize: 12 }}>
            {connected ? 'LIVE' : 'DISCONNECTED'}
          </Text>
        } />
      </div>

      {/* KPI Cards */}
      <StatsCards />

      {/* Row 2: Threat Gauge + Traffic Chart */}
      <Row gutter={[12, 12]}>
        <Col xs={24} md={6}>
          <ThreatGauge />
        </Col>
        <Col xs={24} md={18}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 6 }}>
            <Segmented
              options={[
                { label: 'PPS', value: 'pps' },
                { label: 'BPS', value: 'bps' },
              ]}
              value={chartMode}
              onChange={(v) => setChartMode(v as 'pps' | 'bps')}
              size="small"
            />
          </div>
          <TrafficChart mode={chartMode} />
        </Col>
      </Row>

      {/* Row 3: Protocol Breakdown + Attack Pie */}
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={14}>
          <ProtocolBreakdown />
        </Col>
        <Col xs={24} lg={10}>
          <AttackPanel />
        </Col>
      </Row>

      {/* Row 4: Top Attackers + Mitigation Timeline */}
      <Row gutter={[12, 12]}>
        <Col xs={24} lg={14}>
          <TopAttackers />
        </Col>
        <Col xs={24} lg={10}>
          <MitigationTimeline />
        </Col>
      </Row>

      {/* Row 5: Recent Events */}
      <Row>
        <Col span={24}>
          <EventTable maxRows={8} compact />
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
