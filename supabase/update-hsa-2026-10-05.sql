-- Hindu Student Association: bio and meeting time, as the club asked
--
-- From the bug reporter, Wed 19 Aug 2026, filed from wayzatahsa@gmail.com.
-- The club sent replacement copy and two corrections to when they meet. The
-- report was still open; everything else in it was already applied.
--
-- The old copy said "promoting awareness and appreciation of Hindu culture";
-- the club's own wording leads on celebrating and sharing it, and says plainly
-- that anyone may join. Meeting day changes from the third Wednesday of the
-- month to every other Wednesday, and the time from 3:10-4:10 to 3:30-4:30.

update clubs set
  description = 'Wayzata Hindu Student Association (HSA) is a student-led organization focused on celebrating and sharing Hindu culture, traditions, festivals, and values. The club gives students opportunities to learn about Hindu heritage through cultural activities, discussions, celebrations, and events throughout the school year.',
  detailed_description = 'Wayzata Hindu Student Association (HSA) is a student-led organization focused on celebrating and sharing Hindu culture, traditions, festivals, and values. The club gives students opportunities to learn about Hindu heritage through cultural activities, discussions, celebrations, and events throughout the school year.

Our goal is to create a welcoming community where students can celebrate Hindu culture, learn about its traditions and history, and develop a greater appreciation for cultural diversity. Wayzata HSA is open to all students, regardless of their background or familiarity with Hinduism.',
  target_audience = 'Open to all students, whatever their background or familiarity with Hinduism.',
  meeting_days = 'Every other Wednesday',
  meeting_time = '3:30-4:30 p.m.'
where id = 'hindu-student-association';
