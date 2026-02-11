import React from 'react';
import { Card } from 'antd';
import EventTable from '../components/EventTable';

const EventsPage: React.FC = () => {
  return (
    <Card title="Event Log">
      <EventTable maxRows={500} />
    </Card>
  );
};

export default EventsPage;
