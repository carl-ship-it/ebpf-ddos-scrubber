import React from 'react';
import { Card, Timeline, Tag, Typography } from 'antd';
import {
  WarningOutlined,
  CheckCircleOutlined,
  StopOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { useStore } from '../store';
import dayjs from 'dayjs';

const { Text } = Typography;

const iconMap: Record<string, React.ReactNode> = {
  syn_flood: <ThunderboltOutlined style={{ color: '#f5222d' }} />,
  udp_flood: <WarningOutlined style={{ color: '#fa8c16' }} />,
  dns_amplification: <StopOutlined style={{ color: '#722ed1' }} />,
  ntp_amplification: <StopOutlined style={{ color: '#2f54eb' }} />,
  icmp_flood: <WarningOutlined style={{ color: '#fadb14' }} />,
  ack_flood: <StopOutlined style={{ color: '#eb2f96' }} />,
  fragment: <WarningOutlined style={{ color: '#a0d911' }} />,
};

const colorMap: Record<string, string> = {
  DROP: 'red',
  PASS: 'green',
};

const MitigationTimeline: React.FC = () => {
  const events = useStore((s) => s.events);
  const recent = events.slice(0, 12);

  return (
    <Card title="Mitigation Activity" size="small" style={{ height: '100%' }}>
      <div style={{ maxHeight: 380, overflow: 'auto', paddingRight: 8 }}>
        {recent.length === 0 ? (
          <div style={{ textAlign: 'center', padding: 40, color: 'rgba(255,255,255,0.25)' }}>
            <CheckCircleOutlined style={{ fontSize: 32, marginBottom: 8 }} />
            <div>No recent activity</div>
          </div>
        ) : (
          <Timeline
            items={recent.map((e, i) => ({
              dot: iconMap[e.attackType] || <StopOutlined style={{ color: '#999' }} />,
              children: (
                <div key={i} style={{ paddingBottom: 2 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Tag color={colorMap[e.action] || 'default'} style={{ fontSize: 10 }}>
                      {e.action}
                    </Tag>
                    <Text style={{ color: 'rgba(255,255,255,0.35)', fontSize: 10 }}>
                      {dayjs(e.timestampNs / 1e6).format('HH:mm:ss')}
                    </Text>
                  </div>
                  <div style={{ fontSize: 12, color: 'rgba(255,255,255,0.75)', marginTop: 2 }}>
                    <Text code style={{ fontSize: 11 }}>{e.srcIp}</Text>
                    <span style={{ color: 'rgba(255,255,255,0.3)', margin: '0 4px' }}>&rarr;</span>
                    <Text code style={{ fontSize: 11 }}>{e.dstIp}:{e.dstPort}</Text>
                  </div>
                  <div style={{ fontSize: 11, color: 'rgba(255,255,255,0.45)', marginTop: 1 }}>
                    {e.attackType.replace(/_/g, ' ')} &middot; {e.dropReason.replace(/_/g, ' ')}
                  </div>
                </div>
              ),
            }))}
          />
        )}
      </div>
    </Card>
  );
};

export default MitigationTimeline;
