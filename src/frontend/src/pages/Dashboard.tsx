import React, { useState } from 'react';
import { Row, Col, Segmented } from 'antd';
import StatsCards from '../components/StatsCards';
import TrafficChart from '../components/TrafficChart';
import AttackPanel from '../components/AttackPanel';
import EventTable from '../components/EventTable';

const Dashboard: React.FC = () => {
  const [chartMode, setChartMode] = useState<'pps' | 'bps'>('pps');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* KPI Cards */}
      <StatsCards />

      {/* Traffic Chart */}
      <Row gutter={[16, 16]}>
        <Col span={24}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 8 }}>
            <Segmented
              options={[
                { label: 'PPS', value: 'pps' },
                { label: 'BPS', value: 'bps' },
              ]}
              value={chartMode}
              onChange={(v) => setChartMode(v as 'pps' | 'bps')}
            />
          </div>
          <TrafficChart mode={chartMode} />
        </Col>
      </Row>

      {/* Attack Breakdown + SYN Cookie */}
      <AttackPanel />

      {/* Recent Events (compact) */}
      <Row>
        <Col span={24}>
          <EventTable maxRows={10} compact />
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
